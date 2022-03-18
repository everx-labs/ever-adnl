/*
* Copyright (C) 2019-2021 TON Labs. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

use crate::{
    declare_counted, 
    common::{
        add_counted_object_to_map, add_counted_object_to_map_with_update, 
        add_unbound_object_to_map, add_unbound_object_to_map_with_update,
        AdnlCryptoUtils, AdnlHandshake, AdnlPeers, AdnlPingSubscriber, CountedObject, 
        Counter, hash, Query, QueryCache, QueryId, Subscriber, TARGET, 
        TaggedAdnlMessage, TaggedByteSlice, TaggedTlObject, UpdatedAt, Version
    }
};
#[cfg(feature = "dump")]
use crate::dump;
#[cfg(feature = "telemetry")]
use crate::telemetry::{Metric, MetricBuilder, TelemetryItem, TelemetryPrinter};

use aes_ctr::cipher::stream::SyncStreamCipher;
use ever_crypto::{Ed25519KeyOption, KeyId, KeyOption, KeyOptionJson, sha256_digest};
use rand::Rng;
use std::{
    cmp::{max, min, Ordering}, collections::VecDeque, fmt::{self, Debug, Display, Formatter}, 
    convert::TryInto, io::{Cursor, ErrorKind}, net::{IpAddr, Ipv4Addr, SocketAddr}, 
    sync::{Arc, Condvar, Mutex, atomic::{self, AtomicI32, AtomicU32, AtomicU64, AtomicUsize}},
    time::{Duration, Instant}, thread
};
#[cfg(feature = "dump")]
use std::{fs::{create_dir_all, OpenOptions, rename}, io::Write, path::PathBuf};
use ton_api::{
    deserialize_boxed, IntoBoxed, serialize_boxed, 
    ton::{
        self, TLObject,  
        adnl::{
            Address, Message as AdnlMessage, PacketContents as AdnlPacketContentsBoxed, 
            address::address::Udp, addresslist::AddressList, id::short::Short as AdnlIdShort,  
            message::message::{
                Answer as AdnlAnswerMessage, ConfirmChannel, CreateChannel, 
                Custom as AdnlCustomMessage, Part as AdnlPartMessage, Query as AdnlQueryMessage
            }, 
            packetcontents::PacketContents as AdnlPacketContents
        },
        pub_::publickey::Aes as AesKey
    }
};
#[cfg(feature = "telemetry")]
use ton_api::{tag_from_data};
use ton_types::{error, fail, Result, UInt256};

const TARGET_QUERY: &str = "adnl_query";

#[macro_export]
macro_rules! adnl_node_compatibility_key {
    ($tag: expr, $key: expr) => {
        format!(
            "{{
                \"tag\": {},
                \"data\": {{         
                    \"type_id\": 1209251014,
                    \"pub_key\": \"{}\"
                }}
            }}",
            $tag, 
            $key
        ).as_str()
    }
}

#[macro_export]
macro_rules! adnl_node_test_key {
    ($tag: expr, $key: expr) => {
        format!(
            "{{
                \"tag\": {},
                \"data\": {{         
                    \"type_id\": 1209251014,
                    \"pvt_key\": \"{}\"
                }}
            }}",
            $tag, 
            $key
        ).as_str()
    }
}

#[macro_export]
macro_rules! adnl_node_test_config {
    ($ip: expr, $key:expr) => {
        format!(
            "{{
                \"ip_address\": \"{}\",
                \"keys\": [ 
                    {} 
                ]
            }}",
            $ip, 
            $key
        ).as_str()
    };
    ($ip: expr, $key1:expr, $key2:expr) => {
        format!(
            "{{
                \"ip_address\": \"{}\",
                \"keys\": [ 
                    {}, 
                    {} 
                ]
            }}",
            $ip, 
            $key1,
            $key2
        ).as_str()
    }
}

/// ADNL addresses cache iterator
#[derive(Debug)]
pub struct AddressCacheIterator(u32);

/// ADNL addresses cache
pub struct AddressCache {
    cache: lockfree::map::Map<Arc<KeyId>, u32>,
    index: lockfree::map::Map<u32, Arc<KeyId>>,
    limit: u32,
    upper: AtomicU32
}

impl AddressCache {

    pub fn with_limit(limit: u32) -> Self {
        Self {
            cache: lockfree::map::Map::new(),
            index: lockfree::map::Map::new(),
            limit,
            upper: AtomicU32::new(0),
        }
    }

    pub fn contains(&self, address: &Arc<KeyId>) -> bool {
        self.cache.get(address).is_some()
    }

    pub fn count(&self) -> u32 {
        min(self.upper.load(atomic::Ordering::Relaxed), self.limit)
    }

    pub fn dump(&self) {
        let (mut iter, mut current) = self.first();
        log::debug!(target: TARGET, "ADDRESS CACHE:");
        loop {
            if let Some(peer) = current {
                log::debug!(target: TARGET, "{}", peer)
            } else {
                break
            };
            current = self.next(&mut iter)
        }
    }

    pub fn first(&self) -> (AddressCacheIterator, Option<Arc<KeyId>>) {
        (AddressCacheIterator(0), self.find_by_index(0))
    }

    pub fn given(&self, iter: &AddressCacheIterator) -> Option<Arc<KeyId>> {
        let AddressCacheIterator(ref index) = iter;
        self.find_by_index(*index)
    }

    pub fn next(&self, iter: &mut AddressCacheIterator) -> Option<Arc<KeyId>> {
        let AddressCacheIterator(ref mut index) = iter;
        loop {
            let ret = self.find_by_index({*index += 1; *index});
            if ret.is_some() {
                return ret
            }
            let limit = self.upper.load(atomic::Ordering::Relaxed);
            if *index >= min(limit, self.limit) {
                return None
            }
        }
    }

    pub fn put(&self, address: Arc<KeyId>) -> Result<bool> {
        let mut index = 0;
        let ret = add_unbound_object_to_map(
            &self.cache,
            address.clone(),
            || {
                let upper = self.upper.fetch_add(1, atomic::Ordering::Relaxed);
                index = upper;
                if index >= self.limit {
                    if index >= self.limit * 2 {
                        self.upper.compare_exchange(
                            upper + 1, 
                            index - self.limit + 1, 
                            atomic::Ordering::Relaxed,
                            atomic::Ordering::Relaxed
                        ).ok();
                    }
                    index %= self.limit;
                }
                Ok(index)
            }
        )?;
        if ret {
            if let Some(index) = self.index.insert(index, address) {
                self.cache.remove_with(
                    index.val(),
                    |&(_, val)| {
                        &val == index.key()
                    } 
                );
            }
        }
        Ok(ret)
    }

    pub fn random_set(
        &self, 
        dst: &AddressCache, 
        skip: Option<&lockfree::set::Set<Arc<KeyId>>>,
        n: u32,
    ) -> Result<()> {
        let mut n = min(self.count(), n);
        while n > 0 {
            if let Some(key_id) = self.random(skip) {
                // We do not check success of put due to multithreading
                dst.put(key_id)?;
                n -= 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn random_vec(&self, skip: Option<&Arc<KeyId>>, n: u32) -> Vec<Arc<KeyId>> {
        let max = self.count();
        let mut ret = Vec::new();  
        let mut check = false;
        let mut i = min(max, n);
        while i > 0 {
            if let Some(key_id) = self.index.get(&rand::thread_rng().gen_range(0, max)) {
                let key_id = key_id.val();
                if let Some(skip) = skip {
                    if skip == key_id {   
                        // If there are not enough items in cache, 
                        // reduce limit for skipped element
                        if (n >= max) && !check {
                            check = true;
                            i -= 1;
                        }
                        continue
                    }
                }
                if ret.contains(key_id) {
                    continue
                } else {
                    ret.push(key_id.clone());
                    i -= 1;
                }
            }
        }
        ret
    }
  
    fn find_by_index(&self, index: u32) -> Option<Arc<KeyId>> {
        if let Some(address) = self.index.get(&index) {
            Some(address.val().clone())
        } else {
            None
        }
    }

    fn random(&self, skip: Option<&lockfree::set::Set<Arc<KeyId>>>) -> Option<Arc<KeyId>> {
        let max = self.count();
        // We need a finite loop here because we can test skip set only on case-by-case basis
        // due to multithreading. So it is possible that all items shall be skipped, and with
        // infinite loop we will simply hang
        for _ in 0..10 {
            if let Some(ret) = self.index.get(&rand::thread_rng().gen_range(0, max)) {
                let ret = ret.val();
                if let Some(skip) = skip {
                    if skip.contains(ret) {
                        continue
                    }
                }
                return Some(ret.clone())
            }
        }
        None
    }

}

// ADNL channel
declare_counted!(
    struct AdnlChannel { 
        local_key: Arc<KeyId>,
        other_key: Arc<KeyId>,
        flags: AtomicU64,
        recv: ChannelSide,
        send: ChannelSide
    }
);

struct ChannelSide {
    ordinary: SubchannelSide,
    priority: SubchannelSide
}

struct SubchannelSide {
    id: ChannelId,
    secret: [u8; 32]
}

impl AdnlChannel {

    const ESTABLISHED: u64 = 0x8000000000000000;
    const SEQNO_RESET: u64 = 0x4000000000000000;

    fn with_keys(
        local_key: &Arc<KeyId>, 
        channel_pvt_key: &Arc<dyn KeyOption>, 
        other_key: &Arc<KeyId>,
        channel_pub_key: &[u8; 32],
        counter: Arc<AtomicU64>
    ) -> Result<Self> {
        let fwd_secret = channel_pvt_key.shared_secret(
            channel_pub_key
        )?;
        let cmp = local_key.cmp(other_key);
        let (fwd_secret, rev_secret) = if Ordering::Equal == cmp {
            (fwd_secret, fwd_secret.clone())
        } else {
            let rev_secret = [
                fwd_secret[31], fwd_secret[30], fwd_secret[29], fwd_secret[28], fwd_secret[27], 
                fwd_secret[26], fwd_secret[25], fwd_secret[24], fwd_secret[23], fwd_secret[22], 
                fwd_secret[21], fwd_secret[20], fwd_secret[19], fwd_secret[18], fwd_secret[17],
                fwd_secret[16], fwd_secret[15], fwd_secret[14], fwd_secret[13], fwd_secret[12], 
                fwd_secret[11], fwd_secret[10], fwd_secret[ 9], fwd_secret[ 8], fwd_secret[ 7], 
                fwd_secret[ 6], fwd_secret[ 5], fwd_secret[ 4], fwd_secret[ 3], fwd_secret[ 2],
                fwd_secret[ 1], fwd_secret[ 0]
            ];
            if Ordering::Less == cmp {
                (fwd_secret, rev_secret)
            } else {
                (rev_secret, fwd_secret)
            }
        };
        let ret = Self { 
            local_key: local_key.clone(), 
            other_key: other_key.clone(), 
            flags: AtomicU64::new(0),
            recv: Self::build_side(fwd_secret)?,
            send: Self::build_side(rev_secret)?,
            counter: counter.into()
        };
        Ok(ret)
    }

    fn build_side(ordinary_secret: [u8; 32]) -> Result<ChannelSide> {
        let priority_secret = Self::build_priority_secret(&ordinary_secret);
        let ret = ChannelSide {
            ordinary: SubchannelSide {
                id: Self::calc_id(&ordinary_secret)?, 
                secret: ordinary_secret 
            },
            priority: SubchannelSide {
                id: Self::calc_id(&priority_secret)?, 
                secret: priority_secret 
            }        
        };
        Ok(ret)
    }

    fn build_priority_secret(ordinary_secret: &[u8; 32]) -> [u8; 32] {
        [
            ordinary_secret[ 1], ordinary_secret[ 0], ordinary_secret[ 3], ordinary_secret[ 2],
            ordinary_secret[ 5], ordinary_secret[ 4], ordinary_secret[ 7], ordinary_secret[ 6],
            ordinary_secret[ 9], ordinary_secret[ 8], ordinary_secret[11], ordinary_secret[10],
            ordinary_secret[13], ordinary_secret[12], ordinary_secret[15], ordinary_secret[14],
            ordinary_secret[17], ordinary_secret[16], ordinary_secret[19], ordinary_secret[18],
            ordinary_secret[21], ordinary_secret[20], ordinary_secret[23], ordinary_secret[22],
            ordinary_secret[25], ordinary_secret[24], ordinary_secret[27], ordinary_secret[26],
            ordinary_secret[29], ordinary_secret[28], ordinary_secret[31], ordinary_secret[30]
        ]
    }

    fn calc_id(secret: &[u8; 32]) -> Result<ChannelId> {
        let object = AesKey {
            key: UInt256::with_array(secret.clone())
        };
        hash(object)
    }

    fn decrypt(buf: &mut Vec<u8>, side: &SubchannelSide) -> Result<()> {
        if buf.len() < 64 {
            fail!("Channel message is too short: {}", buf.len())
        }
        Self::process_data(buf, &side.secret)?;
        if !sha256_digest(&buf[64..]).eq(&buf[32..64]) {
            fail!("Bad channel message checksum");
        }
        buf.drain(0..64);
        Ok(())
    }

    fn decrypt_ordinary(&self, buf: &mut Vec<u8>) -> Result<()> {
        Self::decrypt(buf, &self.recv.ordinary)
    }

    fn decrypt_priority(&self, buf: &mut Vec<u8>) -> Result<()> {
        Self::decrypt(buf, &self.recv.priority)
    }

    fn encrypt(buf: &mut Vec<u8>, side: &SubchannelSide) -> Result<()> {
        let checksum = sha256_digest(buf);
        let len = buf.len();
        buf.resize(len + 64, 0);
        buf[..].copy_within(..len, 64);
        buf[..32].copy_from_slice(&side.id);
        buf[32..64].copy_from_slice(&checksum);
        Self::process_data(buf, &side.secret)
    }

    fn encrypt_ordinary(&self, buf: &mut Vec<u8>) -> Result<()> { 
        Self::encrypt(buf, &self.send.ordinary)
    }

    fn encrypt_priority(&self, buf: &mut Vec<u8>) -> Result<()> { 
        Self::encrypt(buf, &self.send.priority)
    }

    fn ordinary_recv_id(&self) -> &ChannelId {
        &self.recv.ordinary.id
    }

    fn ordinary_send_id(&self) -> &ChannelId {
        &self.send.ordinary.id
    }

    fn priority_recv_id(&self) -> &ChannelId {
        &self.recv.priority.id
    }

    fn process_data(buf: &mut Vec<u8>, secret: &[u8; 32]) -> Result<()> {
        AdnlCryptoUtils::build_cipher_secure(
            secret, 
            buf[32..64].try_into()?
        ).apply_keystream(&mut buf[64..]);
        Ok(())
    }

}

struct AdnlNodeAddress {
    channel_key: Arc<dyn KeyOption>,
    ip_address: AtomicU64,
    ip_version: AtomicU32,
    key: Arc<dyn KeyOption>
}

impl AdnlNodeAddress {

    fn from_ip_address_and_key(ip_address: &IpAddress, key: &Arc<dyn KeyOption>) -> Result<Self> {
        let channel_key = Ed25519KeyOption::generate()?;
        let ret = Self {
            channel_key: channel_key,
            ip_address: AtomicU64::new(ip_address.address),
            ip_version: AtomicU32::new(ip_address.version as u32),
            key: key.clone()
        };
        Ok(ret)
    }

    fn update(&self, ip_address: &IpAddress) -> bool {
        const LOCK_BIT: u64 = 0x8000000000000000;
        loop {
            let old_version = self.ip_version.load(atomic::Ordering::Relaxed);
            if old_version >= ip_address.version as u32 {
                 break false
            }
            let old_address = self.ip_address.fetch_or(LOCK_BIT, atomic::Ordering::Relaxed);
            if (old_address & LOCK_BIT) != 0 {
                // Locked for write, concurrent change
                continue
            }
            if self.ip_version.compare_exchange(
                old_version,
                ip_address.version as u32, 
                atomic::Ordering::Relaxed,
                atomic::Ordering::Relaxed
            ).is_err() {
                // Concurrent change, restore data
                self.ip_address.compare_exchange(
                    old_address | LOCK_BIT,
                    old_address, 
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed
                ).ok();
                continue 
            }
            if self.ip_address.compare_exchange(
                old_address | LOCK_BIT,
                ip_address.address,
                atomic::Ordering::Relaxed,
                atomic::Ordering::Relaxed
            ).is_err() {
                // Concurrent change, restore data
                self.ip_version.compare_exchange(
                    ip_address.version as u32,
                    old_version, 
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed
                ).ok();
                continue
            }
            break true
        }
    }

}

/// ADNL node configuration
pub struct AdnlNodeConfig {
    ip_address: IpAddress,
    keys: lockfree::map::Map<Arc<KeyId>, Arc<dyn KeyOption>>,
    tags: lockfree::map::Map<usize, Arc<KeyId>>,
    recv_pipeline_pool: Option<u8>, // %% of cpu cores to assign for recv workers
    recv_priority_pool: Option<u8>, // %% of workers to assign for priority recv
    throughput: Option<u32>
}

#[derive(serde::Deserialize, serde::Serialize)]
struct AdnlNodeKeyJson {
    tag: usize,
    data: KeyOptionJson
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AdnlNodeConfigJson {
    ip_address: String,
    keys: Vec<AdnlNodeKeyJson>,
    recv_pipeline_pool: Option<u8>, // %% of cpu cores to assign for recv workers
    recv_priority_pool: Option<u8>, // %% of workers to assign for priority recv
    throughput: Option<u32>
}

impl AdnlNodeConfigJson {

    /// Get IP address 
    pub fn ip_address(&self) -> Result<IpAddress> {
        IpAddress::from_versioned_string(&self.ip_address, None)
    }   

    /// Get key by tag
    pub fn key_by_tag(&self, tag: usize, as_src: bool) -> Result<Arc<dyn KeyOption>> {
        for key in self.keys.iter() {
            if key.tag == tag {
                return if as_src {
                    Ok(Ed25519KeyOption::from_private_key_json(&key.data)?)
                } else {
                    Ok(Ed25519KeyOption::from_public_key_json(&key.data)?)
                }
            }
        }
        fail!("No keys with tag {} in node config", tag)
    }

}

impl AdnlNodeConfig {

    /// Construct from IP address and key data
    pub fn from_ip_address_and_keys(
        ip_address: &str, 
        keys: Vec<(Arc<dyn KeyOption>, usize)>
    ) -> Result<Self> {
        let ret = AdnlNodeConfig {
            ip_address: IpAddress::from_versioned_string(ip_address, None)?,
            keys: lockfree::map::Map::new(),
            tags: lockfree::map::Map::new(),
            recv_pipeline_pool: None,
            recv_priority_pool: None,
            throughput: None
        };
        for (key, tag) in keys {
            ret.add_key(key, tag)?;
        } 
        Ok(ret)
    }    

    /// Construct from IP address and private key data
    pub fn from_ip_address_and_private_keys(
        ip_address: &str, 
        keytags: Vec<([u8; 32], usize)>
    ) -> Result<(AdnlNodeConfigJson, Self)> {
        let mut keys = Vec::new();
        for (key, tag) in keytags {
            let (json, key) = Ed25519KeyOption::from_private_key_with_json(&key)?;
            keys.push((json, key as Arc<dyn KeyOption>, tag))
        }
        Self::create_configs(ip_address, keys)
    } 
   
    /// Construct from JSON data 
    pub fn from_json(json: &str) -> Result<Self> {
        let json_config: AdnlNodeConfigJson = serde_json::from_str(json)?;
        Self::from_json_config(&json_config)
    }

    /// Construct from JSON config structure
    pub fn from_json_config(json_config: &AdnlNodeConfigJson) -> Result<Self> {
        let ret = AdnlNodeConfig {
            ip_address: json_config.ip_address()?,
            keys: lockfree::map::Map::new(),
            tags: lockfree::map::Map::new(),
            recv_pipeline_pool: json_config.recv_pipeline_pool,
            recv_priority_pool: json_config.recv_priority_pool,
            throughput: json_config.throughput
        };
        for key in json_config.keys.iter() {
            let data = Ed25519KeyOption::from_private_key_json(&key.data)?;
            ret.add_key(data, key.tag)?;
        }
        Ok(ret)
    }

    /// Construct with given IP address (new key pair will be generated)
    pub fn with_ip_address_and_private_key_tags(
        ip_address: &str, 
        tags: Vec<usize>
    ) -> Result<(AdnlNodeConfigJson, Self)> {
        let mut keys = Vec::new();
        for tag in tags {
            let (json, key) = Ed25519KeyOption::generate_with_json()?;
            keys.push((json, key as Arc<dyn KeyOption>, tag))
        }
        Self::create_configs(ip_address, keys)
    }    

    /// Node IP address
    pub fn ip_address(&self) -> &IpAddress {
        &self.ip_address
    }

    /// Node key by ID
    pub fn key_by_id(&self, id: &Arc<KeyId>) -> Result<Arc<dyn KeyOption>> {
        if let Some(key) = self.keys.get(id) {
            Ok(key.val().clone())
        } else {
            fail!("Bad key id {}", id)
        }
    }

    /// Node key by tag
    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<dyn KeyOption>> {
        if let Some(id) = self.tags.get(&tag) {
            self.key_by_id(id.val())
        } else {
            fail!("Bad key tag {}", tag)
        }
    }

    /// Set port number
    pub fn set_port(&mut self, port: u16) {
        self.ip_address.set_port(port)
    }

    /// Set worker pools
    pub fn set_recv_worker_pools(
        &mut self, 
        pipeline_pool: Option<u8>,
        priority_pool: Option<u8>
    ) -> Result<()> {
        self.recv_pipeline_pool = Self::check_percentage_pool(pipeline_pool, "pipeline")?;
        self.recv_priority_pool = Self::check_percentage_pool(priority_pool, "priority")?;
        Ok(())
    }

    /// Set throughput (packets / ms)
    pub fn set_throughput(&mut self, throughput: Option<u32>) {
        self.throughput = if let Some(0) = &throughput {
            None
        } else {
            throughput
        }
    }

    fn add_key(&self, key: Arc<dyn KeyOption>, tag: usize) -> Result<Arc<KeyId>> {
        let mut ret = key.id().clone();
        let added = add_unbound_object_to_map_with_update(
            &self.tags, 
            tag, 
            |found| if let Some(found) = found {
                if found != &ret {
                    fail!("Duplicated key tag {} in node", tag)
                } else {
                    ret = found.clone();
                    Ok(None)
                }
            } else {
                Ok(Some(ret.clone()))
            }
        )?;
        if added {
            add_unbound_object_to_map_with_update(
                &self.keys, 
                ret.clone(), 
                |found| if found.is_some() {
                    fail!("Duplicated key {} in node", ret)
                } else {
                    Ok(Some(key.clone()))
                }
            )?;
        }
        Ok(ret)
    }

    fn create_configs(
        ip_address: &str, 
        keys: Vec<(KeyOptionJson, Arc<dyn KeyOption>, usize)>
    ) -> Result<(AdnlNodeConfigJson, Self)> {
        let mut json_keys = Vec::new();
        let mut tags_keys = Vec::new();
        for (json, key, tag) in keys {
            json_keys.push(
                AdnlNodeKeyJson {
                    tag,
                    data: json
                }
            );
            tags_keys.push((key, tag));
        }
        let json = AdnlNodeConfigJson { 
            ip_address: ip_address.to_string(),
            keys: json_keys,
            recv_pipeline_pool: None,
            recv_priority_pool: None,
            throughput: None
        };
        Ok((json, Self::from_ip_address_and_keys(ip_address, tags_keys)?))
    }    

    fn delete_key(&self, key: &Arc<KeyId>, tag: usize) -> Result<bool> {
        let removed_key = self.keys.remove(key);
        if let Some(removed) = self.tags.remove(&tag) {
            if removed.val() != key {
                fail!("Expected {} key with tag {} but got {}", key, tag, removed.val())
            }
        }
        Ok(removed_key.is_some())
    }

    pub fn check_percentage_pool(pool: Option<u8>, msg: &str) -> Result<Option<u8>> {
        if let Some(pool) = pool {
            if pool == 0 {
                Ok(None)
            } else if pool >= 100 {
                fail!("Bad {} pool ({} %)", msg, pool)
            } else {
                Ok(Some(pool))
            }
        } else {
            Ok(None)
        }
    }

}

pub struct DataCompression;

impl DataCompression {

    const COMPRESSION_LEVEL: i32 = 0;
    const SIZE_COMPRESSION_THRESHOLD: usize = 256;
    const TAG_COMPRESSED: u8 = 0x80;
 
    pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
        let uncompressed = data.len();
        if uncompressed <= Self::SIZE_COMPRESSION_THRESHOLD {
            Ok(data.to_vec())
        } else {
            // Heuristic detection of compressed format: 
            // append original length to the data to be compressed, compress them, 
            // then append tag byte to already compressed data.
            // Data considered to be compressed if their last byte is the same as tag byte.
            // If decompression succeeded, the lengh of the original data must be checked
            let len_bytes = (uncompressed as u32).to_be_bytes();
            let mut ret = Cursor::new(Vec::with_capacity(data.len() + 1));
            zstd::stream::copy_encode(Cursor::new(data), &mut ret, Self::COMPRESSION_LEVEL)?;
            zstd::stream::copy_encode(Cursor::new(&len_bytes), &mut ret, Self::COMPRESSION_LEVEL)?;
            let mut ret = ret.into_inner();
            let compressed = ret.len();
            log::info!(target: TARGET, "Compression: {} -> {}", uncompressed, compressed);
            ret.push(Self::TAG_COMPRESSED);
            Ok(ret)
        }
    } 

    pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
        let len = data.len();
        if len == 0 {
            log::debug!(target: TARGET, "Too short input data for decompression");
            None
        } else {
            match data[len - 1] {
                Self::TAG_COMPRESSED => 
                    match zstd::stream::decode_all(Cursor::new(&data[..len - 1])) {
                        Err(e) => {
                            log::debug!(target: TARGET, "Decompression error: {}", e);
                            None
                        },
                        Ok(mut ret) => {
                            let len = ret.len();
                            if ret.len() < 4 { 
                                None           
                            } else {
                                let src_len = 
                                    ((ret[len - 4] as usize) << 24) | ((ret[len - 3] as usize) << 16) | 
                                    ((ret[len - 2] as usize) <<  8) |  (ret[len - 1] as usize);
                                if src_len != len - 4 {
                                    None
                                } else {
                                    ret.truncate(src_len);
                                    Some(ret)
                                } 
                            }
                        }
                    },
                x => {
                    log::debug!(target: TARGET, "Bad compression tag {:x}", x);
                    None
                }
            }
        }
    }

}

/// IP address internal representation
#[derive(PartialEq)]
pub struct IpAddress {
    address: u64,
    version: i32
}

impl IpAddress {

    /// Construct from string 
    pub fn from_versioned_string(src: &str, version: Option<i32>) -> Result<Self> {
        let addr: SocketAddr = src.parse()?;
        if let IpAddr::V4(ip) = addr.ip() {
            Ok(Self::from_versioned_parts(u32::from_be_bytes(ip.octets()), addr.port(), version))
        } else {
            fail!("IPv6 addressed are not supported")
        }
    }

    /// Convert to UDP data
    pub fn into_udp(&self) -> Udp {
        Udp {
            ip: self.ip() as i32,
            port: self.port() as i32
        }
    }

    fn from_versioned_parts(ip: u32, port: u16, version: Option<i32>) -> Self {
        Self {
            address: ((ip as u64) << 16) | port as u64,
            version: version.unwrap_or_else(|| Version::get())
        }
    }

    fn ip(&self) -> u32 {
        (self.address >> 16) as u32
    }

    fn port(&self) -> u16 {
        self.address as u16
    }

    fn set_ip(&mut self, ip: u32) {
        self.address = ((ip as u64) << 16) | (self.address & 0xFFFF);
        self.version = Version::get();
    }

    fn set_port(&mut self, port: u16) {
        self.address = (self.address & 0xFFFFFFFF0000u64) | port as u64;
        self.version = Version::get();
    }

}

impl Debug for IpAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} version {}", self, self.version)
    }
}

impl Display for IpAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f, 
            "{}.{}.{}.{}:{}", 
            (self.address >> 40) as u8,
            (self.address >> 32) as u8,
            (self.address >> 24) as u8,
            (self.address >> 16) as u8,
            self.address as u16
        )
    }
}

declare_counted!(
    struct Peer {
        address: AdnlNodeAddress,
        recv_state: PeerState,
        send_state: PeerState
    }
);

impl Peer {

    #[cfg(feature = "telemetry")]
    fn print_state_stats(&self, state: &PeerState, local: &Arc<KeyId>) {
        let elapsed = state.start.elapsed().as_secs();
        let bytes = state.bytes.load(atomic::Ordering::Relaxed);
        log::info!(
            target: TARGET, 
            "ADNL STAT {} {}-{}: {} bytes, {} bytes/sec average load",
            state.name,
            local, 
            self.address.key.id(),
            bytes,
            bytes / elapsed
        )
    }

    async fn try_reinit(&self, reinit_date: i32) -> Result<bool> {
        let old_reinit_date = self.send_state.reinit_date();
        match reinit_date.cmp(&old_reinit_date) {
            Ordering::Equal => Ok(true),
            Ordering::Greater => {
                // Refresh reinit state
                self.send_state.reset_reinit_date(reinit_date);
                if old_reinit_date != 0 {
                    self.send_state.reset_seqno().await?;
                    self.recv_state.reset_seqno().await?;
                }
                Ok(true)
            },
            Ordering::Less => Ok(reinit_date == 0)
        }
    }

    #[cfg(feature = "telemetry")]
    fn update_recv_stats(&self, bytes: u64, local: &Arc<KeyId>) {
        self.update_stats(&self.recv_state, bytes, local) 
    }

    #[cfg(feature = "telemetry")]
    fn update_send_stats(&self, bytes: u64, local: &Arc<KeyId>) {
        self.update_stats(&self.send_state, bytes, local) 
    }

    #[cfg(feature = "telemetry")]
    fn update_stats(&self, state: &PeerState, bytes: u64, local: &Arc<KeyId>) {
        if state.update_stats(bytes) {
            self.print_state_stats(state, local);
        }
    }

}

const HISTORY_BITS: usize = 512;
const HISTORY_SIZE: usize = HISTORY_BITS / 64;

struct HistoryLog {
    index: AtomicU64,
    masks: [AtomicU64; HISTORY_SIZE]
}

#[derive(Debug, PartialEq)]
enum MessageRepeat {
    NotNeeded,
    Required,
    Unapplicable
}

declare_counted!(
    struct PacketBuffer {
        buf: Vec<u8>
    }
);

pub struct PeerHistory {
    log: Option<HistoryLog>,
    seqno: AtomicU64
}                                   

impl PeerHistory {

    const INDEX_MASK: u64 = HISTORY_BITS as u64 / 2 - 1;
    const IN_TRANSIT: u64 = 0xFFFFFFFFFFFFFFFF;

    /// Construct for send 
    pub fn for_send() -> Self {
        Self {
            log: None,
            seqno: AtomicU64::new(0)
        }
    }

    /// Construct for recv 
    pub fn for_recv() -> Self {
        let log = HistoryLog {
            index: AtomicU64::new(0),
            masks: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
//                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
//                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
//                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
//                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
//                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
//                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)
            ]
        };
        Self {
            log: Some(log),
            seqno: AtomicU64::new(0)
        }
    }

    /// Print stats
    pub fn print_stats(&self) {
        let seqno = self.seqno.load(atomic::Ordering::Relaxed);
        if let Some(log) = &self.log {
            log::info!(
                target: TARGET, 
                "Peer history: seqno {}/{:x}, mask {:x} [{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x}]",
                seqno, seqno, 
                log.index.load(atomic::Ordering::Relaxed),
                log.masks[0].load(atomic::Ordering::Relaxed),
                log.masks[1].load(atomic::Ordering::Relaxed),
                log.masks[2].load(atomic::Ordering::Relaxed),
                log.masks[3].load(atomic::Ordering::Relaxed),
                log.masks[4].load(atomic::Ordering::Relaxed),
                log.masks[5].load(atomic::Ordering::Relaxed),
                log.masks[6].load(atomic::Ordering::Relaxed),
                log.masks[7].load(atomic::Ordering::Relaxed)
            )
        } else {
            log::info!(target: TARGET, "Peer history: seqno {}/{:x}", seqno, seqno)
        }
    }

    /// Update with specified SEQ number
    pub async fn update(&self, seqno: u64, target: &str) -> Result<bool> {
        if let Some(log) = &self.log {
            self.update_log(log, seqno, target).await 
        } else {
            loop {
                let last_seqno = self.seqno.load(atomic::Ordering::Relaxed);
                if last_seqno < seqno {
                    if self.seqno.compare_exchange(
                        last_seqno,
                        seqno,
                        atomic::Ordering::Relaxed,
                        atomic::Ordering::Relaxed
                    ).is_err() {
                        continue
                    }
                }  
                return Ok(true)
            }
        }
    }

    async fn update_log(&self, log: &HistoryLog, seqno: u64, target: &str) -> Result<bool> {
        let seqno_masked = seqno & Self::INDEX_MASK;
        let seqno_normalized = seqno & !Self::INDEX_MASK; 
        loop {
            let index = log.index.load(atomic::Ordering::Relaxed);
            if index == Self::IN_TRANSIT {
                tokio::task::yield_now().await;
                continue
            }
            let index_masked = index & Self::INDEX_MASK;
            let index_normalized = index & !Self::INDEX_MASK;
            if index_normalized > seqno_normalized + Self::INDEX_MASK + 1 {
                // Out of the window
                log::trace!(
                    target: target,
                    "Peer packet with seqno {:x} is too old ({:x})", 
                    seqno, 
                    index_normalized
                );
                return Ok(false)
            }
            // Masks format: 
            // lower0, lower1, lower2, lower3, upper0, upper1, upper2, upper3
            let mask = 1 << seqno_masked % 64;
            let mask_offset = if index_normalized > seqno_normalized {
                // Lower part of the window
                Some(0)
            } else if index_normalized == seqno_normalized {
                // Upper part of the window
                Some(HISTORY_SIZE / 2)
            } else {
                None
            };
            let next_index = if let Some(mask_offset) = mask_offset {
                let mask_offset = mask_offset + seqno_masked as usize / 64;
                let already_received = 
                    log.masks[mask_offset].load(atomic::Ordering::Relaxed) & mask;
                if log.index.load(atomic::Ordering::Relaxed) != index {
                    continue
                }
                if already_received != 0 {
                    // Already received
                    log::trace!(
                        target: target, 
                        "Peer packet with seqno {:x} was already received", 
                        seqno
                    );
                    return Ok(false)
                }
                if log.index.compare_exchange(
                    index, 
                    Self::IN_TRANSIT, 
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed
                ).is_err() {
                    continue
                }
                log.masks[mask_offset].fetch_or(mask, atomic::Ordering::Relaxed);
                index
            } else {
                if log.index.compare_exchange(
                    index, 
                    Self::IN_TRANSIT, 
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed
                ).is_err() {
                    continue
                }
                if index_normalized + Self::INDEX_MASK + 1 == seqno_normalized {
                    for i in 0..HISTORY_SIZE / 2 {
                        log.masks[i].store(
                            log.masks[i + HISTORY_SIZE / 2].load(atomic::Ordering::Relaxed),
                            atomic::Ordering::Relaxed
                        )
                    }
                    for i in HISTORY_SIZE / 2..HISTORY_SIZE {
                        log.masks[i].store(0, atomic::Ordering::Relaxed)
                    }
                } else {
                    for i in 0..HISTORY_SIZE {
                        log.masks[i].store(0, atomic::Ordering::Relaxed)
                    }
                }
                seqno_normalized
            };
            let last_seqno = self.seqno.load(atomic::Ordering::Relaxed);
            if last_seqno < seqno {
                self.seqno.store(seqno, atomic::Ordering::Relaxed)
            }
            let index_masked = (index_masked + 1) & !Self::INDEX_MASK;
            if log.index.compare_exchange(
                Self::IN_TRANSIT, 
                next_index | index_masked,
                atomic::Ordering::Relaxed,
                atomic::Ordering::Relaxed
            ).is_err() {
                fail!("INTERNAL ERROR: Peer packet seqno sync mismatch ({:x})", seqno)
            }
            break
        }
        Ok(true)
    }

    async fn reset(&self, seqno: u64) -> Result<()> {
        if let Some(log) = &self.log {
            loop {
                let index = log.index.load(atomic::Ordering::Relaxed);
                if index == Self::IN_TRANSIT {
                    tokio::task::yield_now().await;
                    continue
                }
                if log.index.compare_exchange(
                    index, 
                    Self::IN_TRANSIT, 
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed
                ).is_err() {
                    continue
                }
                break
            }
            for i in 0..HISTORY_SIZE {
                log.masks[i].store(
                    if i == HISTORY_SIZE / 2 {
                        1
                    } else {
                        0
                    }, 
                    atomic::Ordering::Relaxed
                )
            }
        }
        self.seqno.store(seqno, atomic::Ordering::Relaxed);
        if let Some(log) = &self.log {
            if log.index.compare_exchange(
                Self::IN_TRANSIT, 
                seqno & !Self::INDEX_MASK,
                atomic::Ordering::Relaxed,
                atomic::Ordering::Relaxed
            ).is_err() {
                fail!("INTERNAL ERROR: peer packet seqno reset mismatch ({:x})", seqno)
            }
        }
        Ok(())
    }

}

struct PeerState {
    ordinary_history: PeerHistory,
    priority_history: PeerHistory,
    reinit_date: AtomicI32,
    #[cfg(feature = "telemetry")]
    name: &'static str,
    #[cfg(feature = "telemetry")]
    start: Instant,
    #[cfg(feature = "telemetry")]
    print: AtomicU64,
    #[cfg(feature = "telemetry")]
    bytes: AtomicU64,
    #[cfg(feature = "telemetry")]
    packets: Arc<MetricBuilder>
}

impl PeerState {

    fn for_receive_with_reinit_date(
        reinit_date: i32,
        #[cfg(feature = "telemetry")]
        node: &AdnlNode,
        #[cfg(feature = "telemetry")]
        peers: &AdnlPeers
    ) -> Self {
        Self {
            ordinary_history: PeerHistory::for_recv(),
            priority_history: PeerHistory::for_recv(),
            reinit_date: AtomicI32::new(reinit_date),
            #[cfg(feature = "telemetry")]
            name: "recv",
            #[cfg(feature = "telemetry")]
            start: Instant::now(),
            #[cfg(feature = "telemetry")]
            print: AtomicU64::new(0),
            #[cfg(feature = "telemetry")]
            bytes: AtomicU64::new(0),
            #[cfg(feature = "telemetry")]
            packets: Self::add_metric(node, peers, "packets/sec", false)
        }
    }

    fn for_send(
        #[cfg(feature = "telemetry")]
        node: &AdnlNode,
        #[cfg(feature = "telemetry")]
        peers: &AdnlPeers
    ) -> Self {
        Self {
            ordinary_history: PeerHistory::for_send(),
            priority_history: PeerHistory::for_send(),
            reinit_date: AtomicI32::new(0),
            #[cfg(feature = "telemetry")]
            name: "send",
            #[cfg(feature = "telemetry")]
            start: Instant::now(),
            #[cfg(feature = "telemetry")]
            print: AtomicU64::new(0),
            #[cfg(feature = "telemetry")]
            bytes: AtomicU64::new(0),
            #[cfg(feature = "telemetry")]
            packets: Self::add_metric(node, peers, "packets/sec", true)
        }
    }

    fn next_seqno(&self, priority: bool) -> u64 {
        if priority { 
            self.priority_history.seqno.fetch_add(1, atomic::Ordering::Relaxed) + 1
        } else {
            self.ordinary_history.seqno.fetch_add(1, atomic::Ordering::Relaxed) + 1
        }
    }

    fn reinit_date(&self) -> i32 {
        self.reinit_date.load(atomic::Ordering::Relaxed)
    }

    fn reset_reinit_date(&self, reinit_date: i32) {
        self.reinit_date.store(reinit_date, atomic::Ordering::Relaxed)
    }

    async fn reset_seqno(&self) -> Result<()> {
        self.ordinary_history.reset(0).await?;
        self.priority_history.reset(0).await
    }

    fn seqno(&self, priority: bool) -> u64 {
        if priority {
            self.priority_history.seqno.load(atomic::Ordering::Relaxed)
        } else {
            self.ordinary_history.seqno.load(atomic::Ordering::Relaxed)
        }
    }

    async fn save_seqno(&self, seqno: u64, priority: bool) -> Result<bool> {
        if priority {
            self.priority_history.update(seqno, TARGET).await
        } else {
            self.ordinary_history.update(seqno, TARGET).await
        }
    }

    #[cfg(feature = "telemetry")]
    fn add_metric(
        node: &AdnlNode, 
        peers: &AdnlPeers, 
        tag: &str, 
        send: bool
    ) -> Arc<MetricBuilder> {
        let local = peers.local().to_string();
        let other = peers.other().to_string();
        let name = if send { 
            format!("{}->{} {}", &local[..6], &other[..6], tag)
        } else {
            format!("{}<-{} {}", &local[..6], &other[..6], tag)
        };
        let ret = Telemetry::create_metric_builder(name.as_str());
        node.telemetry.printer.add_metric(TelemetryItem::MetricBuilder(ret.clone()));
        ret
    }

    #[cfg(feature = "telemetry")]
    fn update_stats(&self, bytes: u64) -> bool {
        self.packets.update(1);
        self.bytes.fetch_add(bytes, atomic::Ordering::Relaxed);
        let elapsed = self.start.elapsed().as_secs();
        if elapsed > self.print.load(atomic::Ordering::Relaxed) {
            self.print.store(elapsed + 5, atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }

}

struct Peers {
    channels_send: Arc<ChannelsSend>,
    channels_wait: Arc<ChannelsSend>,
    map_of: lockfree::map::Map<Arc<KeyId>, Peer>
}

impl Peers {
    fn with_incinerator(
        incinerator: &lockfree::map::SharedIncin<Arc<KeyId>, Arc<AdnlChannel>>
    ) -> Arc<Self> {
        let ret = Peers {
            map_of: lockfree::map::Map::new(),
            channels_send: Arc::new(lockfree::map::Map::with_incin(incinerator.clone())),
            channels_wait: Arc::new(lockfree::map::Map::with_incin(incinerator.clone()))
        };
        Arc::new(ret)
    }
}

struct Queue<T> {
    queue: lockfree::queue::Queue<T>,
    #[cfg(feature = "telemetry")]
    count: AtomicU64,
    #[cfg(feature = "telemetry")]
    metric: Arc<Metric>
}

impl <T> Queue<T> {

    fn new(
        #[cfg(feature = "telemetry")]
        metric: Arc<Metric>
    ) -> Self {
        Self {
            #[cfg(feature = "telemetry")]
            count: AtomicU64::new(0),
            queue: lockfree::queue::Queue::new(),
            #[cfg(feature = "telemetry")]
            metric
        }
    }

    fn put(&self, item: T) {
        #[cfg(feature = "telemetry")]
        self.count.fetch_add(1, atomic::Ordering::Relaxed);
        self.queue.push(item);
    }

    fn get(&self) -> Option<T> {
        let ret = self.queue.pop();
        #[cfg(feature = "telemetry")] 
        if ret.is_some() {
            let count = self.count.fetch_sub(1, atomic::Ordering::Relaxed);
            self.metric.update(count)
        }
        ret
    }
    
}

struct QuerySendContext {
    channel: Option<Arc<AdnlChannel>>,
    query_id: QueryId, 
    repeat: MessageRepeat,
    reply_ping: Arc<tokio::sync::Barrier>
}

struct RecvPipeline {                        	
    adnl: Arc<AdnlNode>, 
//    count: AtomicU64,
    max_workers: u64,
    max_ordinary_workers: u64,
    ordinary: Queue<(PacketBuffer, Subchannel)>,
    priority: Queue<(PacketBuffer, Subchannel)>,
    proc_ordinary_packets: AtomicU64,
    proc_priority_packets: AtomicU64,
    runtime: tokio::runtime::Handle,
    subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
    #[cfg(feature = "static_workers")]
    sync: lockfree::queue::Queue<tokio::sync::oneshot::Sender<bool>>,
    workers: AtomicU64,
}

impl RecvPipeline {

    fn with_params(
        adnl: Arc<AdnlNode>, 
        runtime: tokio::runtime::Handle, 
        subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
    ) -> Self {
        let mut max_workers = if let Some(pool) = adnl.config.recv_pipeline_pool {
            max(1, num_cpus::get() as u64 * pool as u64 / 100) 
        } else  {
            num_cpus::get() as u64
        };
        if max_workers > AdnlNode::MAX_PACKETS_IN_PROGRESS {
            max_workers = AdnlNode::MAX_PACKETS_IN_PROGRESS
        }
        let max_ordinary_workers = if let Some(pool) = adnl.config.recv_priority_pool {
            let max_ordinary_workers = max(1, max_workers * (100 - pool as u64) / 100);
            if max_ordinary_workers == max_workers {
                max_workers += 1
            } 
            max_ordinary_workers
        } else {
            max_workers
        };
        Self {
            adnl: adnl.clone(),
//            count: AtomicU64::new(0),
            max_workers,
            max_ordinary_workers,
            ordinary: Queue::new(
                #[cfg(feature = "telemetry")]
                adnl.telemetry.ordinary.recv_queue_packets.clone()
            ),
            priority: Queue::new(
                #[cfg(feature = "telemetry")]
                adnl.telemetry.priority.recv_queue_packets.clone()
            ),
            proc_ordinary_packets: AtomicU64::new(0),
            proc_priority_packets: AtomicU64::new(0),
            runtime, 
            subscribers,
            #[cfg(feature = "static_workers")]
            sync: lockfree::queue::Queue::new(),
            workers: AtomicU64::new(0)
        }
    }
                                                                                                                    
    async fn get(&self) -> Option<(PacketBuffer, Subchannel, bool)> {
        loop {
            let ret = if let Some((data, subchannel)) = self.priority.get() {
                self.proc_priority_packets.fetch_add(1, atomic::Ordering::Relaxed);
                Some((data, subchannel, true))
            } else {
                loop {
                    let ordinary = self.proc_ordinary_packets.load(atomic::Ordering::Relaxed);
                    if ordinary >= self.max_ordinary_workers {
                        break None
                    } 
                    if self.proc_ordinary_packets.compare_exchange(
                        ordinary,
                        ordinary + 1,
                        atomic::Ordering::Relaxed,
                        atomic::Ordering::Relaxed
                    ).is_err() {
                        continue
                    }
                    if let Some((data, subchannel)) = self.ordinary.get() {
                        break Some((data, subchannel, false))                    
                    } else {
                        self.proc_ordinary_packets.fetch_sub(1, atomic::Ordering::Relaxed);
                        break None
                    }
                }
            };
            if ret.is_some() {
//                self.count.fetch_sub(1, atomic::Ordering::Relaxed);
                break ret
            }
/*
            if self.count.load(atomic::Ordering::Relaxed) > 0 {
                continue
            }
*/
            #[cfg(feature = "static_workers")] {
//            tokio::time::sleep(Duration::from_millis(1)).await;
                let (sender, reader) = tokio::sync::oneshot::channel();
                self.sync.push(sender);
                if let Ok(true) = reader.await {
                    continue
                }
            }
            break None
        }        
    }

    fn put(self: Arc<Self>, data: PacketBuffer, subchannel: Subchannel) {
        if let Subchannel::Priority(_) = &subchannel {
            self.priority.put((data, subchannel));
        } else {
            self.ordinary.put((data, subchannel));
        }
//        self.count.fetch_add(1, atomic::Ordering::Relaxed);
        #[cfg(feature = "static_workers")]
        if let Some(sender) = self.sync.pop() {
            sender.send(true).ok();
        }
        self.spawn();
    }

    async fn shutdown(&self) {
        loop {
            #[cfg(feature = "static_workers")]
            while let Some(sender) = self.sync.pop() {
                sender.send(false).ok();
            }
            if self.workers.load(atomic::Ordering::Relaxed) == 0 {
                break
            }
            tokio::task::yield_now().await
        }
    }

    fn spawn(self: Arc<Self>) {
        loop {
            let workers = self.workers.load(atomic::Ordering::Relaxed);
            if workers >= self.max_workers {
                return
            }    
            if self.workers.compare_exchange(
                workers,
                workers + 1,
                atomic::Ordering::Relaxed,
                atomic::Ordering::Relaxed
            ).is_ok() {
                break
            }
        }    
        self.clone().runtime.spawn(
            async move {
                loop {
                    let (mut packet, subchannel, priority) = match self.get().await {
                        Some(job) => job,
                        None => break
                    };
                    #[cfg(feature = "telemetry")] 
                    self.update_metric(priority);
                    match self.adnl.process_packet(
                        &mut packet, 
                        subchannel, 
                        &self.subscribers
                    ).await {
                        Err(e) => {
                            log::warn!(target: TARGET, "ERROR <-- {}", e);
                            #[cfg(feature = "telemetry")] 
                            if priority {
                                self.adnl.telemetry.priority.proc_invalid.update(1)
                            } else {
                                self.adnl.telemetry.ordinary.proc_invalid.update(1)
                            }
                        },
                        _ => ()
                    }
                    if priority {
                        self.proc_priority_packets.fetch_sub(1, atomic::Ordering::Relaxed);
                    } else {
                        self.proc_ordinary_packets.fetch_sub(1, atomic::Ordering::Relaxed);
                    }
                    #[cfg(feature = "telemetry")] 
                    self.update_metric(priority);
                }
                self.workers.fetch_sub(1, atomic::Ordering::Relaxed);
            }
        );
    }

    #[cfg(feature = "telemetry")]
    fn update_metric(&self, priority: bool) {
        if priority {
            self.adnl.telemetry.priority.proc_packets.update(
                self.proc_priority_packets.load(atomic::Ordering::Relaxed)
            )
        } else {
            self.adnl.telemetry.ordinary.proc_packets.update(
                self.proc_ordinary_packets.load(atomic::Ordering::Relaxed)
            )
        }
    }

}

struct SendData {
    destination: u64,
    data: Vec<u8>
}

impl Debug for SendData {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "destination {:x}, data {:x?}", self.destination, self.data)
    }
}

#[derive(Debug)]
enum SendJob {
    Data(SendData),
    Stop
}

struct SendPipeline {
//    count: AtomicU64,
    ordinary: Queue<SendJob>,
    priority: Queue<SendJob>,
    lock: Mutex<()>,
    sync: Condvar
}

impl SendPipeline {

    const TIMEOUT_WAIT_QUEUE_MS: u64 = 10; 

    fn new(
        #[cfg(feature = "telemetry")]
        ordinary_metric: Arc<Metric>,
        #[cfg(feature = "telemetry")]
        priority_metric: Arc<Metric>
    ) -> Self {
        Self {
//            count: AtomicU64::new(0),
            ordinary: Queue::new(
                #[cfg(feature = "telemetry")]
                ordinary_metric
            ),
            priority: Queue::new(
                #[cfg(feature = "telemetry")]
                priority_metric
            ),
            lock: Mutex::new(()),
            sync: Condvar::new()
        }
    }

    fn get(&self) -> Result<SendJob> {
        loop {
            let ret = if let Some(ret) = self.priority.get() {
                Some(ret)
            } else {
                self.ordinary.get()
            };
            if let Some(ret) = ret {
//                self.count.fetch_sub(1, atomic::Ordering::Relaxed);
                return Ok(ret)
            }
//            if self.count.load(atomic::Ordering::Relaxed) > 0 {
//                continue
//            }
            let _mux = self.sync.wait_timeout(
                self.lock.lock().map_err(|_| error!("Queue mutex poisoned"))?,
                Duration::from_millis(Self::TIMEOUT_WAIT_QUEUE_MS)
            ).map_err(|_| error!("Queue wait failed"))?;
        }        
    }

    fn put_ordinary(&self, job: SendJob) {
        self.put(&self.ordinary, job)
    }

    fn put_priority(&self, job: SendJob) {
        self.put(&self.priority, job)
    }

    fn put(&self, queue: &Queue<SendJob>, job: SendJob) {
//      self.count.fetch_add(1, atomic::Ordering::Relaxed);
        queue.put(job);
        self.sync.notify_one();
    }

    fn shutdown(&self) {
        self.put_priority(SendJob::Stop)
    }

}

#[derive(Clone)]
enum Subchannel {
    None,
    Ordinary(Arc<AdnlChannel>),
    Priority(Arc<AdnlChannel>)
}

// ADNL transfer
declare_counted!(
    struct Transfer {
        data: lockfree::map::Map<usize, Vec<u8>>,
        received: AtomicUsize,
        total: usize,
        updated: UpdatedAt
    }
);

type ChannelId = [u8; 32];
type ChannelsRecv = lockfree::map::Map<ChannelId, Subchannel>; 
type ChannelsSend = lockfree::map::Map<Arc<KeyId>, Arc<AdnlChannel>>;
type TransferId = [u8; 32];

#[cfg(feature = "telemetry")]
struct TelemetryAlloc {
    channels: Arc<Metric>,
    checkers: Arc<Metric>,
    packets: Arc<Metric>,
    peers: Arc<Metric>,
    transfers: Arc<Metric>
}

#[cfg(feature = "telemetry")]
struct TelemetryByStage {
    proc_packets: Arc<Metric>,          // Packets in processing
    proc_invalid: Arc<MetricBuilder>,   // Packets with errors in processing
    proc_skipped: Arc<MetricBuilder>,   // Skipped packets (due to failed checks)
    proc_success: Arc<MetricBuilder>,   // Packets successfully processed
    proc_unknown: Arc<MetricBuilder>,   // Packets to unknown address
    recv_queue_packets: Arc<Metric>,    // Queued received packets
    send_queue_packets: Arc<Metric>,    // Queued packets to send
    send_tags: lockfree::map::Map<u32, Arc<MetricBuilder>>,
}

#[cfg(feature = "telemetry")]
impl TelemetryByStage {
    fn with_priority(priority: bool) -> Self {
        let priority = if priority {
            "priority"
        } else {
            "ordinary"
        };
        Self {
            proc_packets: Telemetry::create_metric(
                format!("{} packets, in progress", priority).as_str()
            ),
            proc_invalid: Telemetry::create_metric_builder(
                format!("proc {} invalid, packets/sec", priority).as_str()
            ),
            proc_skipped: Telemetry::create_metric_builder(
                format!("proc {} skipped, packets/sec", priority).as_str()
            ),
            proc_success: Telemetry::create_metric_builder(
                format!("proc {} success, packets/sec", priority).as_str()
            ),
            proc_unknown: Telemetry::create_metric_builder(
                format!("proc {} unknown, packets/sec", priority).as_str()
            ),
            recv_queue_packets: Telemetry::create_metric(
                format!("{} packets, recv queue", priority).as_str()
            ),
            send_queue_packets: Telemetry::create_metric(
                format!("{} packets, send queue", priority).as_str()
            ),
            send_tags: lockfree::map::Map::new()
        } 
    }
}

#[cfg(feature = "telemetry")]
declare_counted!(
    struct TelemetryCheck {
        start: Instant,
        info: String
    }
);

#[cfg(feature = "telemetry")]
struct Telemetry {
    ordinary: TelemetryByStage,
    priority: TelemetryByStage,
    recv_sock: Arc<MetricBuilder>,
    send_sock: Arc<MetricBuilder>,
    allocated: TelemetryAlloc,
    check_id: AtomicU64,
    check_map: lockfree::map::Map::<u64, TelemetryCheck>,
    check_queue: lockfree::queue::Queue<u64>,
    checkers: Arc<AtomicU64>,
    printer: TelemetryPrinter
}

#[cfg(feature = "telemetry")]
impl Telemetry {

    const PERIOD_AVERAGE_SEC: u64 = 5;    
    const PERIOD_MEASURE_NANO: u64 = 1000000000;    
    const TIMEOUT_PROCESSING_MS: u64 = 500;    

    fn add_check(&self, info: String) -> Result<u64> {
        loop {
            let id = self.check_id.fetch_add(1, atomic::Ordering::Relaxed);
            let added = add_counted_object_to_map(
                &self.check_map,
                id,
                || {
                    let check = TelemetryCheck {
                        start: Instant::now(),
                        info: info.clone(),
                        counter: self.checkers.clone().into()
                    };
                    self.allocated.checkers.update(self.checkers.load(atomic::Ordering::Relaxed));
                    Ok(check)
                }
            )?;
            if added {
                self.check_queue.push(id);
                break Ok(id)
            }
        }
    }

    fn create_metric(name: &str) -> Arc<Metric> {
        Metric::without_totals(name, Self::PERIOD_AVERAGE_SEC)
    }

    fn create_metric_with_total(name: &str) -> Arc<Metric> {
	Metric::with_total_amount(name, Self::PERIOD_AVERAGE_SEC)
    }

    fn create_metric_builder(name: &str) -> Arc<MetricBuilder> {
        MetricBuilder::with_metric_and_period(
            Self::create_metric_with_total(name),
            Self::PERIOD_MEASURE_NANO
        )
    }

    fn drop_check(&self, id: u64) {
        self.check_map.remove(&id);
    }

    fn evaluate_checks(&self) {
        let mut until = None;
        while let Some(id) = self.check_queue.pop() {
            if let Some(until_id) = &until {
                if *until_id == id {
                    self.check_queue.push(id);
                    break
                }
            } 
            if let Some(check) = self.check_map.get(&id) {
                let check = check.val();
                let elapsed = check.start.elapsed().as_millis() as u64;
                if elapsed >= Self::TIMEOUT_PROCESSING_MS {
                    log::warn!(
                        target: TARGET, 
                        "Too long processing of {}: {} ms", 
                        check.info, 
                        elapsed
                    ) 
                }
                if until.is_none() {
                    until.replace(id);
                }
                self.check_queue.push(id)
            }
        }
    }

    fn get_message_info(msg: &AdnlMessage) -> String {
        match msg {
            AdnlMessage::Adnl_Message_Part(part) => 
                format!("AdnlMessagePart offset {} of {}", part.offset, part.total_size),
            AdnlMessage::Adnl_Message_Answer(answer) => 
                format!("AdnlMessageAnswer tag {:08x}", tag_from_data(&answer.answer)),
            AdnlMessage::Adnl_Message_ConfirmChannel(_) => 
                "AdnlMessageConfirmChannel".to_string(),
            AdnlMessage::Adnl_Message_CreateChannel(_) =>
                "AdnlMessageCreateChannel".to_string(),
            AdnlMessage::Adnl_Message_Custom(custom) =>
                format!("AdnlMessageCustom tag {:08x}", tag_from_data(&custom.data)),
            AdnlMessage::Adnl_Message_Nop =>
                "AdnlMessageNop".to_string(),
            AdnlMessage::Adnl_Message_Query(query) => {
                let data = &query.query;
                let mut tag = tag_from_data(data);
                // Uncover Overlay.Query internal message if possible
                if (tag == 0xCCFD8443) && (data.len() >= 40) {
                    tag = tag_from_data(&data[36..]);
                    format!("AdnlMessageQuery/OverlayQuery tag {:08x}", tag)
                } else {
                    format!("AdnlMessageQuery tag {:08x}", tag)
                }
            },
            AdnlMessage::Adnl_Message_Reinit(_) =>
                "AdnlMessageReinit".to_string()
        }
    }

}

#[cfg(feature = "dump")]
#[derive(Debug)]
struct DumpRecord {
    alive: bool,
    key_id: Arc<KeyId>,
    msg: String
}

#[cfg(feature = "dump")]
struct Dump {
    path: PathBuf,
    reader: lockfree::queue::Queue<tokio::sync::mpsc::UnboundedReceiver<DumpRecord>>,
    sender: tokio::sync::mpsc::UnboundedSender<DumpRecord>
}

type LoopbackReader = tokio::sync::mpsc::UnboundedReceiver<(AdnlMessage, Arc<KeyId>)>;
type LoopbackSender = tokio::sync::mpsc::UnboundedSender<(AdnlMessage, Arc<KeyId>)>;

struct AdnlAlloc {
    channels: Arc<AtomicU64>,
    packets: Arc<AtomicU64>,
    peers: Arc<AtomicU64>,
    transfers: Arc<AtomicU64>
}

/// ADNL node
pub struct AdnlNode {
    channels_incinerator: lockfree::map::SharedIncin<Arc<KeyId>, Arc<AdnlChannel>>,
    channels_recv: Arc<ChannelsRecv>,
    config: AdnlNodeConfig,
    options: AtomicU32,
    peers: lockfree::map::Map<Arc<KeyId>, Arc<Peers>>,
    queries: Arc<QueryCache>, 
    queue_monitor_queries: lockfree::queue::Queue<(u64, QueryId)>,
    queue_send_loopback_packets: LoopbackSender,
    queue_send_loopback_readers: lockfree::queue::Queue<LoopbackReader>,
    send_pipeline: SendPipeline,
    start_time: i32,
    stop: Arc<AtomicU32>,
    transfers: Arc<lockfree::map::Map<TransferId, Arc<Transfer>>>,
    #[cfg(feature = "telemetry")]                                
    telemetry: Telemetry,
    allocated: AdnlAlloc,
    #[cfg(feature = "dump")] 
    dump: Option<Dump>                               
}

impl Drop for AdnlNode {
    fn drop(&mut self) {
        log::warn!(target: TARGET, "ADNL node dropped");
    }
}

impl AdnlNode {

    /// ADNL options
    pub const OPTION_FORCE_VERSIONING:  u32 = 0x0001; // Force protocol versioning
    pub const OPTION_FORCE_COMPRESSION: u32 = 0x0002; // Force traffic compression

    const CLOCK_TOLERANCE_SEC: i32 = 60; 
    const MAX_ADNL_MESSAGE: usize = 1024;
    const MAX_PACKETS_IN_PROGRESS: u64 = 512;
    const MAX_PRIORITY_ATTEMPTS: u64 = 10;
    const SIZE_BUFFER: usize = 2048;
    const TIMEOUT_ADDRESS_SEC: i32 = 1000;       
    const TIMEOUT_CHANNEL_RESET_SEC: u64 = 30;   
    const TIMEOUT_QUERY_MIN_MS: u64 = 500;   
    const TIMEOUT_QUERY_MAX_MS: u64 = 5000; 
    const TIMEOUT_QUERY_STOP_MS: u64 = 1; 
    const TIMEOUT_SHUTDOWN_MS: u64 = 2000; 
    const TIMEOUT_TRANSFER_SEC: u64 = 5;
    
    /// Constructor
    pub async fn with_config(
        mut config: AdnlNodeConfig,
        #[cfg(feature = "dump")]                                
        dump_path: Option<PathBuf>
    ) -> Result<Arc<Self>> {
        let incinerator = lockfree::map::SharedIncin::new();
        let peers = lockfree::map::Map::new();
        let mut added = false;
        for key in config.keys.iter() {
            peers.insert(key.val().id().clone(), Peers::with_incinerator(&incinerator));
            added = true
        }
        if !added {
            fail!("No keys configured for node");
        }
        if config.ip_address.ip() == 0 {
            let ip = external_ip::ConsensusBuilder::new()
               .add_sources(external_ip::get_http_sources::<external_ip::Sources>())
               .build()
               .get_consensus().await;
            if let Some(IpAddr::V4(ip)) = ip {
                config.ip_address.set_ip(u32::from_be_bytes(ip.octets()))
            } else {
                fail!("Cannot obtain own external IP address");
            }
        }
        let (queue_send_loopback_sender, queue_send_loopback_reader) = 
            tokio::sync::mpsc::unbounded_channel();
        #[cfg(feature = "telemetry")] 
        let telemetry = {
            let ordinary  = TelemetryByStage::with_priority(false);
            let priority  = TelemetryByStage::with_priority(true);
            let recv_sock = Telemetry::create_metric_builder("socket recv, packets/sec");
            let send_sock = Telemetry::create_metric_builder("socket send, packets/sec");
            let allocated = TelemetryAlloc {
                channels: Telemetry::create_metric("Alloc ADNL channels"),
                checkers: Telemetry::create_metric("Alloc ADNL checkers"),
                packets: Telemetry::create_metric("Alloc ADNL recv packets"),
                peers: Telemetry::create_metric("Alloc ADNL peers"),
                transfers: Telemetry::create_metric("Alloc ADNL transfers")
            };
            let printer = TelemetryPrinter::with_params(
                Telemetry::PERIOD_AVERAGE_SEC, 
                vec![
                    TelemetryItem::MetricBuilder(recv_sock.clone()),
                    TelemetryItem::Metric(priority.recv_queue_packets.clone()),
                    TelemetryItem::Metric(ordinary.recv_queue_packets.clone()),
                    TelemetryItem::Metric(priority.proc_packets.clone()), 
                    TelemetryItem::MetricBuilder(priority.proc_invalid.clone()),
                    TelemetryItem::MetricBuilder(priority.proc_unknown.clone()),
                    TelemetryItem::MetricBuilder(priority.proc_skipped.clone()),
                    TelemetryItem::MetricBuilder(priority.proc_success.clone()),
                    TelemetryItem::Metric(ordinary.proc_packets.clone()),
                    TelemetryItem::MetricBuilder(ordinary.proc_invalid.clone()),
                    TelemetryItem::MetricBuilder(ordinary.proc_unknown.clone()),
                    TelemetryItem::MetricBuilder(ordinary.proc_skipped.clone()),
                    TelemetryItem::MetricBuilder(ordinary.proc_success.clone()),
                    TelemetryItem::Metric(priority.send_queue_packets.clone()),
                    TelemetryItem::Metric(ordinary.send_queue_packets.clone()),
                    TelemetryItem::MetricBuilder(send_sock.clone()),
                    TelemetryItem::Metric(allocated.packets.clone()),
                    TelemetryItem::Metric(allocated.channels.clone()),
                    TelemetryItem::Metric(allocated.peers.clone()),
                    TelemetryItem::Metric(allocated.transfers.clone()),
                    TelemetryItem::Metric(allocated.checkers.clone()),
                ]
            );
            Telemetry {
                ordinary,
                priority,
                recv_sock,
                send_sock,
                allocated,
                check_id: AtomicU64::new(0),
                check_map: lockfree::map::Map::new(),
                check_queue: lockfree::queue::Queue::new(), 
                checkers: Arc::new(AtomicU64::new(0)),
                printer
            }
        };
        let allocated = AdnlAlloc {
            channels: Arc::new(AtomicU64::new(0)),
            packets: Arc::new(AtomicU64::new(0)),
            peers: Arc::new(AtomicU64::new(0)), 
            transfers: Arc::new(AtomicU64::new(0))
        };
        let ret = Self {
            channels_incinerator: incinerator, 
            channels_recv: Arc::new(lockfree::map::Map::new()), 
            config, 
            options: AtomicU32::new(0),
            peers,
            queries: Arc::new(lockfree::map::Map::new()), 
            queue_monitor_queries: lockfree::queue::Queue::new(),
            queue_send_loopback_packets: queue_send_loopback_sender,
            queue_send_loopback_readers: lockfree::queue::Queue::new(),
            send_pipeline: SendPipeline::new(
                #[cfg(feature = "telemetry")]
                telemetry.ordinary.send_queue_packets.clone(),
                #[cfg(feature = "telemetry")]
                telemetry.priority.send_queue_packets.clone()
            ),
            start_time: Version::get(),
            stop: Arc::new(AtomicU32::new(0)),
            transfers: Arc::new(lockfree::map::Map::new()),
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
            #[cfg(feature = "dump")]
            dump: if let Some(dump_path) = dump_path {
                let (sender, reader) = tokio::sync::mpsc::unbounded_channel();
                let dump = Dump {
                    path: dump_path,
                    reader: lockfree::queue::Queue::new(),
                    sender
                };
                dump.reader.push(reader);
                Some(dump)
            } else {
                None
            }
        };
        ret.queue_send_loopback_readers.push(queue_send_loopback_reader);
        Ok(Arc::new(ret))
    }

    pub fn check(&self) {
//        if self.queue_send_packets.count.load(atomic::Ordering::Relaxed) != 0 {
//            panic!("Fuckup with queue")
//        }
    }

    /// Start node 
    pub async fn start(
        node: &Arc<Self>, 
        mut subscribers: Vec<Arc<dyn Subscriber>>
    ) -> Result<()> {
        let mut queue_send_loopback_reader = None;
        for _ in 0..1 {
            match node.queue_send_loopback_readers.pop() {
                Some(reader) => queue_send_loopback_reader = Some(reader),
                _ => fail!("ADNL node already started")
            }
        }
        let mut queue_send_loopback_reader = queue_send_loopback_reader.ok_or_else(
            || error!("Loopback reader is not set")
        )?;
        let socket_recv = socket2::Socket::new(
            socket2::Domain::ipv4(), 
            socket2::Type::dgram(), 
            None
        )?;
//        socket_recv.set_send_buffer_size(1 << 26)?;
        socket_recv.set_recv_buffer_size(1 << 20)?;        
//        socket_recv.set_nonblocking(true)?;
        socket_recv.bind(
            &SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED), 
                node.config.ip_address.port()
            ).into()
        )?;
        let socket_send = socket_recv.try_clone()?;
//        let socket_send = Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);
//        let socket_send = tokio::net::UdpSocket::bind(
//            &SocketAddr::new(
//                IpAddr::V4(Ipv4Addr::UNSPECIFIED), 
//                node.config.ip_address.port()
//            )
//        ).await?;
//        let socket_send = Arc::new(socket_send);
        subscribers.push(Arc::new(AdnlPingSubscriber));
        // Subscribers poll
        let start = Arc::new(Instant::now());
        let subscribers = Arc::new(subscribers);
        let subscribers_local = subscribers.clone();
        let subscribers_stop = Arc::new(AtomicU32::new(0));
        for subscriber in subscribers.iter() {
            let node_subs = node.clone();
            let start = start.clone();
            let subscriber = subscriber.clone();
            let subscribers_stop = subscribers_stop.clone();
            subscribers_stop.fetch_add(1, atomic::Ordering::Relaxed);
            tokio::spawn(
                async move {
                    loop {
                        tokio::time::sleep(
                            Duration::from_millis(Self::TIMEOUT_QUERY_STOP_MS)
                        ).await;
                        if node_subs.stop.load(atomic::Ordering::Relaxed) > 0 {      
                            break
                        }  
                        subscriber.poll(&start).await;
                    }
                    if subscribers_stop.fetch_sub(1, atomic::Ordering::Relaxed) == 1 {
                        node_subs.stop.fetch_add(1, atomic::Ordering::Relaxed);                                                                                                         
                        log::warn!(target: TARGET, "Node subscriber poll exited");
                    }
                }
            );
        }
        let recv_pipeline = Arc::new(
            RecvPipeline::with_params(
                node.clone(), 
                tokio::runtime::Handle::current().clone(), 
                subscribers
            )
        );
        // Stopping watchdog
        let node_stop = node.clone();
        let recv_stop = recv_pipeline.clone();
        tokio::spawn(
            async move {
                let mut monitor_queries: Vec<(u128, QueryId)> = Vec::new();
                #[cfg(feature = "telemetry")] 
                let mut last_check = Instant::now();
                loop {
                    tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP_MS)).await;
                    #[cfg(feature = "telemetry")] {
                        node_stop.telemetry.allocated.channels.update(
                            node_stop.allocated.channels.load(atomic::Ordering::Relaxed)
                        );
                        node_stop.telemetry.allocated.checkers.update(
                            node_stop.telemetry.checkers.load(atomic::Ordering::Relaxed)
                        );
                        node_stop.telemetry.allocated.packets.update(
                            node_stop.allocated.packets.load(atomic::Ordering::Relaxed)
                        );
                        node_stop.telemetry.allocated.peers.update(
                            node_stop.allocated.peers.load(atomic::Ordering::Relaxed)
                        );
                        node_stop.telemetry.allocated.transfers.update(
                            node_stop.allocated.transfers.load(atomic::Ordering::Relaxed)
                        );
                        node_stop.telemetry.printer.try_print();
                        if last_check.elapsed().as_secs() >= Telemetry::PERIOD_AVERAGE_SEC {
                            node_stop.telemetry.evaluate_checks();
                            last_check = Instant::now();
                        }
                    }
                    if node_stop.stop.load(atomic::Ordering::Relaxed) > 0 {      
                        node_stop.send_pipeline.shutdown();
                        let stop = (
                            AdnlMessage::Adnl_Message_Nop,
                            KeyId::from_data([0u8; 32])
                        );
                        if let Err(e) = node_stop.queue_send_loopback_packets.send(stop) {
                            log::warn!(target: TARGET, "Cannot close node loopback: {}", e);
                        }
                        recv_stop.shutdown().await;
                        #[cfg(feature = "dump")]
                        if let Some(dump) = node_stop.dump.as_ref() {
                            let stop = DumpRecord {
                                alive: false,
                                key_id: KeyId::from_data([0u8; 32]),
                                msg: String::new()
                            };
                            if let Err(e) = dump.sender.send(stop) {
                                log::warn!(target: TARGET, "Cannot close node dump: {}", e);
                            }
                        } 
                        break
                    }
                    let elapsed = start.elapsed().as_millis();
                    let mut drop = monitor_queries.len(); 
                    while drop > 0 {
                        let (timeout, query_id) = monitor_queries[drop - 1];
                        if timeout > elapsed {
                            break
                        }
                        log::info!(
                            target: TARGET_QUERY, 
                            "Try dropping query {:02x}{:02x}{:02x}{:02x}", 
                            query_id[0], query_id[1], query_id[2], query_id[3]
                        );
                        match Self::update_query(&node_stop.queries, query_id, None).await {
                            Err(e) => log::info!(
                                target: TARGET_QUERY, 
                                "ERROR: {} when dropping query {:02x}{:02x}{:02x}{:02x}", 
                                e, query_id[0], query_id[1], query_id[2], query_id[3]
                            ),
                            Ok(true) => log::info!(
                                target: TARGET_QUERY, 
                                "Dropped query {:02x}{:02x}{:02x}{:02x}", 
                                query_id[0], query_id[1], query_id[2], query_id[3]
                            ),
                            _ => ()
                        }
                        drop -= 1;
                    };
                    monitor_queries.drain(drop..);
                    while let Some((timeout, query_id)) = node_stop.queue_monitor_queries.pop() {
                        let mut insert = monitor_queries.len();
                        let elapsed = elapsed + timeout as u128;
                        while insert > 0 {
                            let (timeout, _) = monitor_queries[insert - 1];
                            if timeout >= elapsed {
                                break
                            }
                            insert -= 1;
                        }
                        monitor_queries.insert(insert, (elapsed, query_id));
                    }
                }
                node_stop.stop.fetch_add(1, atomic::Ordering::Relaxed);                                                                                                         
                log::warn!(target: TARGET, "Node stopping watchdog exited");
            }
        );
        // Remote connections
        let node_recv = node.clone();
        thread::spawn(
            move || {
                let mut buf = [0u8; Self::SIZE_BUFFER];
                loop {
                    if node_recv.stop.load(atomic::Ordering::Relaxed) > 0 {
                        break
                    }
                    let len = match socket_recv.recv(&mut buf[..]) {
                        Ok(len) => if len == 0 {
                            continue
                        } else if len < 32 {
                            log::warn!(target: TARGET, "ERROR <-- Packet is too short ({})", len);
                            continue                                           	
                        } else {
                            len
                        }, 
                        Err(err) => {
                            match err.kind() {
                                ErrorKind::WouldBlock => thread::yield_now(),
                                _ => log::warn!(target: TARGET, "ERROR <-- {}", err)
                            }
                            continue
                        }
                    };
                    #[cfg(feature = "telemetry")]
                    node_recv.telemetry.recv_sock.update(1);
                    let mut packet = PacketBuffer {
                        buf: Vec::with_capacity(len),
                        counter: node_recv.allocated.packets.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    node_recv.telemetry.allocated.packets.update(
                        node_recv.allocated.packets.load(atomic::Ordering::Relaxed)
                    );
                    packet.buf.extend_from_slice(&buf[..len]);
                    let subchannel = node_recv.channels_recv.get(&packet.buf[0..32]).map_or(
                        Subchannel::None,
                        |subchannel| subchannel.val().clone()
                    );
                    recv_pipeline.clone().put(packet, subchannel);
                }
                node_recv.stop.fetch_add(1, atomic::Ordering::Relaxed);
                log::warn!(target: TARGET, "Node socket receiver exited");
            }
        );
        let node_send = node.clone();
        thread::spawn(
            move || {
                const PERIOD_NANOS: u128 = 1000000;
                let start_history = Instant::now();
                let mut history = None;
                loop {
                    let job = node_send.send_pipeline.get();
                    let (job, stop) = match job {
                        Ok(SendJob::Data(job)) => (job, false),
                        Ok(SendJob::Stop) => (
                            // Send closing packet to 127.0.0.1:port
                            SendData { 
                                destination: 
                                    0x7F0000010000u64 | node_send.config.ip_address.port() as u64,
                                data: Vec::new()
                            },
                            true
                        ),
                        Err(e) => {
                            log::error!(target: TARGET, "ERROR in send queue --> {}", e);
                            continue
                        }
                    };
                    // Manage the throughput
                    if let Some(throughput) = &node_send.config.throughput {
                        let history = history.get_or_insert_with(
                            || VecDeque::with_capacity(*throughput as usize)
                        );
                        if history.len() >= *throughput as usize {
                            if let Some(time) = history.pop_front() {
                                while start_history.elapsed().as_nanos() - time < PERIOD_NANOS {
                                    thread::yield_now()
                                }
                            }
                        }
                        history.push_back(start_history.elapsed().as_nanos());
                    }
                    let addr: socket2::SockAddr = SocketAddr::new(
                        IpAddr::from(((job.destination >> 16) as u32).to_be_bytes()), 
                        job.destination as u16
                    ).into();
                    loop {
                        match socket_send.send_to(&job.data[..], &addr) {
                            Ok(size) => if size != job.data.len() {
                                log::error!(
                                    target: TARGET, 
                                    "Incomplete send: {} bytes of {}", 
                                    size, 
                                    job.data.len()
                                )
                            },
                            Err(err) => match err.kind() {
                                ErrorKind::WouldBlock => {
                                    thread::yield_now();
                                    continue
                                },
                                _ => log::error!(target: TARGET, "ERROR --> {}", err)
                            }
                        }
                        break
                    }
                    #[cfg(feature = "telemetry")] 
                    node_send.telemetry.send_sock.update(1);
                    if node_send.stop.load(atomic::Ordering::Relaxed) > 0 {
                        if stop {
                            break
                        }
                    }
                }
                node_send.stop.fetch_add(1, atomic::Ordering::Relaxed);
                log::warn!(target: TARGET, "Node socket sender exited");
            }
        );
        // Local connections
        let node_loop = node.clone();
        tokio::spawn(
            async move {
                while let Some((msg, src)) = queue_send_loopback_reader.recv().await {
                    if node_loop.stop.load(atomic::Ordering::Relaxed) > 0 {
                        break
                    }
                    let query = match msg {
                        AdnlMessage::Adnl_Message_Query(query) => query,
                        x => {
                            log::warn!(target: TARGET, "Unsupported local ADNL message {:?}", x);
                            continue;
                        }
                    };
                    let node_loop = node_loop.clone();
                    let peers_local = AdnlPeers::with_keys(src.clone(), src.clone());
                    let subscribers_local = subscribers_local.clone();
                    tokio::spawn(
                        async move {
                            let answer = match Self::process_query(
                                &subscribers_local, 
                                &query,
                                &peers_local
                            ).await {
                                Ok(Some(answer)) => answer,
                                Err(e) => {
                                    log::warn!(target: TARGET, "ERROR --> {}", e);
                                    return
                                },
                                _ => return
                            };
                            let answer = match answer.object {
                                AdnlMessage::Adnl_Message_Answer(answer) => answer,
                                x => {
                                    log::warn!(target: TARGET, "Unexpected reply {:?}", x);
                                    return
                                }
                            };
                            if let Err(e) = node_loop.process_answer(&answer, &src).await {
                                log::warn!(target: TARGET, "ERROR --> {}", e);
                            }
                        }            
                    );
                }
                Self::graceful_close(queue_send_loopback_reader).await;
                node_loop.stop.fetch_add(1, atomic::Ordering::Relaxed);
                log::warn!(target: TARGET, "Node loopback exited");
            }
        );
        // Traffic dump
        #[cfg(feature = "dump")]
        if let Some(dump) = node.dump.as_ref() {
            let node_dump = node.clone();
            let mut dump_path = PathBuf::from(&dump.path);  
            dump_path.push("alive");
            create_dir_all(&dump_path)?;
            dump_path.pop();
            if let Some(mut reader) = dump.reader.pop() {
                tokio::spawn(
                    async move {
                        fn prepare(path: &PathBuf, file: &String, alive: bool) -> Result<PathBuf> {
                            let dst = if alive {
                                path.join("alive").join(file)
                            } else {
                                path.join(file)
                            };
                            if !dst.exists() {
                                let src = if alive {
                                    path.join(file)
                                } else {
                                    path.join("alive").join(file)
                                };
                                if src.exists() {
                                    rename(src, dst.as_path())?
                                }
                            }
                            Ok(dst)
                        }
                        fn print(path: PathBuf, msg: String) -> Result<()> {
                            let mut file = OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(path)?;
                            writeln!(file, "{}", msg)?;
                            Ok(())
                        }
                        while let Some(record) = reader.recv().await {
                            if node_dump.stop.load(atomic::Ordering::Relaxed) > 0 {
                                break
                            }
                            let file = format!("{}", record.key_id).replace("/", "_");
                            let file = match prepare(&dump_path, &file, record.alive) {
                                Ok(file) => file, 
                                Err(e) => {
                                    log::warn!(target: TARGET, "Error during dump: {}", e);
                                    continue
                                }
                            };
                            if let Err(e) = print(file, record.msg) {
                                log::warn!(target: TARGET, "Error during dump: {}", e);
                            }
                        }
                        Self::graceful_close(reader).await;
                        node_dump.stop.fetch_add(1, atomic::Ordering::Relaxed);
                        log::warn!(target: TARGET, "Node dump exited");
                    }
                );
            }
        }
        Ok(())
    }       

    /// Stop node
    pub async fn stop(&self) {
        log::warn!(target: TARGET, "Stopping ADNL node");
        self.stop.fetch_add(1, atomic::Ordering::Relaxed);
        let wait_until = {
            #[cfg(feature = "dump")]
            if self.dump.is_some() {
                7
            } else {
                6 
            }
            #[cfg(not(feature = "dump"))]
            6
        };
        loop {
            tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP_MS)).await;
            if self.stop.load(atomic::Ordering::Relaxed) >= wait_until {
                break
            }
        }
        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_SHUTDOWN_MS)).await;
        log::warn!(target: TARGET, "ADNL node stopped");
    }

    /// Add key
    pub fn add_key(&self, key: Arc<dyn KeyOption>, tag: usize) -> Result<Arc<KeyId>> {
        let ret = self.config.add_key(key, tag)?;
        add_unbound_object_to_map(
            &self.peers,
            ret.clone(),
            || Ok(Peers::with_incinerator(&self.channels_incinerator))
        )?;
        Ok(ret)
    }

    /// Add dynamic telemetry metric
    #[cfg(feature = "telemetry")]
    pub fn add_metric(&self, name: &str) -> Arc<Metric> {
        let ret = Telemetry::create_metric(name);
        self.telemetry.printer.add_metric(TelemetryItem::Metric(ret.clone()));
        ret
    }
    
    /// Add peer 
    pub fn add_peer(
        &self, 
        local_key: &Arc<KeyId>, 
        peer_ip_address: &IpAddress, 
        peer_key: &Arc<dyn KeyOption>
    ) -> Result<Option<Arc<KeyId>>> {
        if peer_key.id() == local_key {
            return Ok(None)
        }
        let mut error = None;
        let mut ret = peer_key.id().clone();
        let result = self.peers(local_key)?.map_of.insert_with(
            ret.clone(), 
            |key, inserted, found| if let Some((_, found)) = found {
                ret = key.clone();
                found.address.update(peer_ip_address);
                lockfree::map::Preview::Discard
            } else if inserted.is_some() {
                ret = key.clone(); 
                lockfree::map::Preview::Keep
            } else {
                let address = AdnlNodeAddress::from_ip_address_and_key(peer_ip_address, peer_key);
                match address {
                    Ok(address) => {
                        #[cfg(feature = "telemetry")]
                        let peers = AdnlPeers::with_keys(local_key.clone(), ret.clone());
                        let peer = Peer {
                            address,
                            recv_state: PeerState::for_receive_with_reinit_date(
                                self.start_time,
                                #[cfg(feature = "telemetry")]
                                self, 
                                #[cfg(feature = "telemetry")]
                                &peers
                            ),
                            send_state: PeerState::for_send(
                                #[cfg(feature = "telemetry")]
                                self, 
                                #[cfg(feature = "telemetry")]
                                &peers
                            ),
                            counter: self.allocated.peers.clone().into()
                        };
                        #[cfg(feature = "telemetry")]
                        self.telemetry.allocated.peers.update(
                            self.allocated.peers.load(atomic::Ordering::Relaxed)
                        );
                        lockfree::map::Preview::New(peer)
                    },
                    Err(err) => {
                        error = Some(err);
                        lockfree::map::Preview::Discard
                    }
                }
            }
        );                      
        if let Some(error) = error {
            return Err(error)
        } 
        if let lockfree::map::Insertion::Created = result {
            log::debug!(
                target: TARGET, 
                "Added ADNL peer with IP {}, keyID {}, key {} to {}",
                peer_ip_address,  
                base64::encode(peer_key.id().data()),
                base64::encode(peer_key.pub_key()?),
                base64::encode(local_key.data())
            )
        }
        Ok(Some(ret))
    }

    /// Build address list for given node
    pub fn build_address_list(&self, expire_at: Option<i32>) -> Result<AddressList> {
        let version = Version::get();
        let ret = AddressList {
            addrs: vec![self.config.ip_address.into_udp().into_boxed()].into(),
            version,
            reinit_date: self.start_time,
            priority: 0,
            expire_at: expire_at.unwrap_or(0)
        };
        Ok(ret)
    }

    /// Calculate timeout from roundtrip, milliseconds
    pub fn calc_timeout(roundtrip: Option<u64>) -> u64 {
        let timeout = roundtrip.unwrap_or(Self::TIMEOUT_QUERY_MAX_MS);
        if timeout < Self::TIMEOUT_QUERY_MIN_MS {
            Self::TIMEOUT_QUERY_MIN_MS
        } else {
            timeout
        }
    }

    /// Check protocol options
    pub fn check_options(&self, options: u32) -> bool {
        (self.options.load(atomic::Ordering::Relaxed) & options) == options
    }

    /// Delete key
    pub fn delete_key(&self, key: &Arc<KeyId>, tag: usize) -> Result<bool> {
        self.peers.remove(key);
        self.config.delete_key(key, tag)
    }

    /// Delete peer
    pub fn delete_peer(&self, local_key: &Arc<KeyId>, peer_key: &Arc<KeyId>) -> Result<bool> {
        let peers = self.peers.get(local_key).ok_or_else(
            || error!("Try to remove peer {} from unknown local key {}", peer_key, local_key)
        )?;
        Ok(peers.val().map_of.remove(peer_key).is_some())
    }

    /// Node IP address
    pub fn ip_address(&self) -> &IpAddress {
        self.config.ip_address()
    }

    /// Node key by ID
    pub fn key_by_id(&self, id: &Arc<KeyId>) -> Result<Arc<dyn KeyOption>> {
        self.config.key_by_id(id)
    }

    /// Node key by tag
    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<dyn KeyOption>> {
        self.config.key_by_tag(tag)
    }

    /// Parse other's address list
    pub fn parse_address_list(list: &AddressList) -> Result<Option<IpAddress>> { 
        if list.addrs.is_empty() {
            log::warn!(target: TARGET, "Address list is empty");
            return Ok(None)
        }
        let version = Version::get();
        if list.reinit_date > version + Self::CLOCK_TOLERANCE_SEC {
            log::warn!(
                target: TARGET, 
                "Address list is too new: {} vs {}",
                list.reinit_date, version
            );
            return Ok(None)
        } 
/*
        if (list.version > version) || (list.reinit_date > version) {
            fail!("Address list version is too high: {} vs {}", list.version, version)
        }
*/
        if (list.expire_at != 0) && (list.expire_at < version) {
            log::warn!(target: TARGET, "Address list is expired");
            return Ok(None)
        }
        match &list.addrs[0] {
            Address::Adnl_Address_Udp(x) => {
                let ret = IpAddress::from_versioned_parts(
                    x.ip as u32,
                    x.port as u16,
                    Some(list.version)
                );
                Ok(Some(ret))
            },
            _ => {
                log::warn!(target: TARGET, "Only IPv4 address format is supported");
                Ok(None)
            }
        }
    }

    /// Send query
    pub async fn query(
        self: Arc<AdnlNode>, 
        query: &TaggedTlObject,
        peers: &AdnlPeers,
        timeout: Option<u64>
    ) -> Result<Option<TLObject>> {
        self.query_with_prefix(None, query, peers, timeout).await
    }

    /// Send query with prefix
    pub async fn query_with_prefix(
        self: Arc<AdnlNode>,  
        prefix: Option<&[u8]>,
        query: &TaggedTlObject,
        peers: &AdnlPeers,
        timeout: Option<u64>
    ) -> Result<Option<TLObject>> {

        fn get_query_print_id(context: &QuerySendContext, priority: bool) -> String { 
            format!(
                "{} query {:02x}{:02x}{:02x}{:02x}",
                if priority {
                    "priority"
                } else {
                    "ordinary"
                },
                context.query_id[0], context.query_id[1], 
                context.query_id[2], context.query_id[3]
            )
        }
 
        async fn wait_query(
            node: Arc<AdnlNode>, 
            context: Arc<QuerySendContext>,
            peers: &AdnlPeers
        ) -> Result<Option<TLObject>> { 
            context.reply_ping.wait().await;
            node.process_query_result(context, peers)
        }

        let priority_context = self.clone().send_query_with_priority(
            prefix, query, peers, timeout, true
        ).await?;

        if let MessageRepeat::Required = priority_context.repeat {
            let ordinary_context = self.clone().send_query_with_priority(
                prefix, query, peers, timeout, false
            ).await;
            match ordinary_context {
                Err(e) => {
                    log::warn!(
                        target: TARGET, 
                        "Error when send query in ordinary subchannel: {}", 
                        e
                    ); 
                    wait_query(self, priority_context, peers).await
                },
                Ok(ordinary_context) => {
                    let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();
                    let sender = Arc::new(sender);
                    let cloned_peers = peers.clone();
                    let cloned_sender = sender.clone();
                    let context = priority_context.clone();
                    let node = self.clone();
                    tokio::spawn(
                        async move {
                            cloned_sender.send(
                                (wait_query(node, context, &cloned_peers).await, true)
                            )
                        }
                    );
                    let cloned_peers = peers.clone();
                    let cloned_sender = sender.clone();
                    let context = ordinary_context.clone();
                    let node = self.clone();
                    tokio::spawn(
                        async move {
                            cloned_sender.send(
                                (wait_query(node, context, &cloned_peers).await, false)
                            )
                        }
                    );
                    let reply = if let Some((reply, priority)) = reader.recv().await {
                        let context = if priority {
                            priority_context
                        } else {
                            ordinary_context
                        };
                        match &reply {
                            Err(e) => {
                                let id = get_query_print_id(&context, priority);
                                log::warn!(target: TARGET, "Error with {} reply: {}", id, e);
                                None
                            },
                            Ok(None) => {
                                let id = get_query_print_id(&context, priority);
                                log::info!(target: TARGET, "No reply to {}", id);
                                None
                            },
                            Ok(Some(_)) => Some(reply)
                        }
                    } else {
                        reader.close();
                        fail!(
                            "INTERNAL ERROR: 1st query reply to {:?} read mismatch", 
                            query.object
                        );
                    };
                    if let Some(reply) = reply {
                        tokio::spawn(
                            async move {
                                if reader.recv().await.is_some() {
                                    Self::graceful_close(reader).await
                                } else {
                                    log::warn!(
                                        target: TARGET, 
                                        "INTERNAL ERROR: query reply flush mismatch"
                                    )
                                }
                            }
                        );
                        reply
                    } else if let Some((reply, _)) = reader.recv().await {
                        Self::graceful_close(reader).await;
                        reply
                    } else {
                        reader.close();
                        fail!(
                            "INTERNAL ERROR: 2nd query reply to {:?} read mismatch", 
                            query.object
                        );
                    }
                }
            }
        } else {
            wait_query(self, priority_context, peers).await
        }

    }

    /// Reset peers 
    pub fn reset_peers(&self, to_reset: &AdnlPeers) -> Result<()> {
        let local_key = to_reset.local();
        let other_key = to_reset.other();
        let peers = self.peers(local_key)?;
        let peer = peers.map_of.get(other_key).ok_or_else(
            || error!("Try to reset unknown peer pair {} -> {}", local_key, other_key)
        )?;
        log::warn!(target: TARGET, "Resetting peer pair {} -> {}", local_key, other_key);
        let peer = peer.val();
        let address = AdnlNodeAddress::from_ip_address_and_key(
            &IpAddress {
                address: peer.address.ip_address.load(atomic::Ordering::Relaxed),
                version: Version::get()
            },
            &peer.address.key
        )?;
        peers.channels_wait
            .remove(other_key)
            .or_else(|| peers.channels_send.remove(other_key))
            .and_then(
                |removed| {
                    let peer = Peer {
                        address,
                        recv_state: PeerState::for_receive_with_reinit_date(
                            peer.recv_state.reinit_date.load(atomic::Ordering::Relaxed) + 1,
                            #[cfg(feature = "telemetry")]
                            self, 
                            #[cfg(feature = "telemetry")]
                            to_reset
                        ),
                        send_state: PeerState::for_send(
                            #[cfg(feature = "telemetry")]
                            self, 
                            #[cfg(feature = "telemetry")]
                            to_reset
                        ),
                        counter: self.allocated.peers.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    self.telemetry.allocated.peers.update(
                        self.allocated.peers.load(atomic::Ordering::Relaxed)
                    );
                    peers.map_of.insert(other_key.clone(), peer);
                    self.drop_receive_subchannels(removed.val())
                }
             );
        Ok(())
    }

    /// Send custom message
    pub fn send_custom(
        &self, 
        data: &TaggedByteSlice, 
        peers: AdnlPeers,
    ) -> Result<()> {
        let msg = TaggedAdnlMessage {
            object: AdnlCustomMessage {
                data: ton::bytes(data.object.to_vec())
            }.into_boxed(),
            #[cfg(feature = "telemetry")]
            tag: data.tag
        };
        let (_, repeat) = self.send_message_to_peer(msg, &peers, false)?;
        match repeat {
            MessageRepeat::Unapplicable => Ok(()), 
            x => fail!("INTERNAL ERROR: bad repeat {:?} in ADNL custom message", x)
        }
    }

    /// Set ADNL options
    pub fn set_options(&self, options: u32) {
        self.options.fetch_or(options, atomic::Ordering::Relaxed);
    }

    async fn add_subchannels(&self, channel: Arc<AdnlChannel>, wait: bool) -> Result<()> {
        let peers = self.peers(&channel.local_key)?;
        let peer = peers.map_of.get(&channel.other_key).ok_or_else(
            || error!("Cannot add subchannels to unknown peer {}", channel.other_key)
        )?;
        let peer = peer.val();
        let added = if wait {
            let mut prev = None;
            let added = add_counted_object_to_map_with_update(
                &peers.channels_wait,
                channel.other_key.clone(),
                |found| {
                    prev = if let Some(found) = found {
                        if found.send.ordinary.id == channel.send.ordinary.id {
                            return Ok(None)
                        }
                        Some(found.clone())
                    } else {
                        None
                    };
                    Ok(Some(channel.clone()))
                }
            )?;
            if added {
                prev.or_else(
                    || if let Some(removed) = peers.channels_send.remove(&channel.other_key) {
                        Some(removed.val().clone())
                    } else {
                        None
                    }
                ).and_then(
                    |removed| self.drop_receive_subchannels(&removed)
                );
            }
            added
        } else {
            add_counted_object_to_map_with_update(
                &peers.channels_send,
                channel.other_key.clone(),
                |found| {
                    if let Some(found) = found {
                        if found.send.ordinary.id == channel.send.ordinary.id {
                            return Ok(None)
                        }
                    }
                    Ok(Some(channel.clone()))
                }
            )?
        };
        if !added {
            let ch = if wait {
                peers.channels_wait.get(&channel.other_key)
            } else {
                peers.channels_send.get(&channel.other_key)
            };
            if let Some(ch) = ch {
                let ch = ch.val();
                while ch.flags.load(atomic::Ordering::Relaxed) & AdnlChannel::SEQNO_RESET == 0 {
                    tokio::task::yield_now().await
                }
                return Ok(())
            } else {
                fail!("INTERNAL ERROR: mismatch in channel adding")
            }
        }
        self.channels_recv.insert(
            channel.ordinary_recv_id().clone(), 
            Subchannel::Ordinary(channel.clone())
        );
        self.channels_recv.insert(
            channel.priority_recv_id().clone(), 
            Subchannel::Priority(channel.clone())
        );
        peer.send_state.priority_history.reset(0).await?;
        peer.recv_state.priority_history.reset(0).await?;
        let flags = channel.flags.fetch_or(
            AdnlChannel::SEQNO_RESET, 
            atomic::Ordering::Relaxed
        );
        if flags & AdnlChannel::SEQNO_RESET != 0 {
            fail!("INTERNAL ERROR: mismatch in channel seqno reset")
        }
        Ok(())
    }

    async fn check_packet(
        &self,
        packet: &AdnlPacketContents, 
        priority: bool,
        local_key: &Arc<KeyId>,
        channel: Option<&Arc<AdnlChannel>>
    ) -> Result<Option<Arc<KeyId>>> {

        fn check_signature(
            packet: &AdnlPacketContents, 
            key: &Arc<dyn KeyOption>,
            mandatory: bool
        ) -> Result<()> {
            if let Some(signature) = &packet.signature {
                let mut to_sign = packet.clone();
                to_sign.signature = None;
                key.verify(&serialize_boxed(&to_sign.into_boxed())?, &signature)
            } else if mandatory {
                fail!("No mandatory signature in ADNL packet")
            } else {
                Ok(())
            }
        } 

        let (ret, mut address_reinit_date, check) = if let Some(channel) = &channel {
            if packet.from.is_some() || packet.from_short.is_some() {
                fail!("Explicit source address inside channel packet")
            }
            (channel.other_key.clone(), None, true)
        } else if let Some(pub_key) = &packet.from {
            let key = Ed25519KeyOption::from_public_key_tl(pub_key)?;
            let other_key = key.id().clone();
            if let Some(id) = &packet.from_short {
                if other_key.data() != id.id.as_slice() {
                    fail!("Mismatch between ID and key inside packet")
                }
            }
            check_signature(packet, &key, true)?;
            if let Some(address) = &packet.address {
                if let Some(ip_address) = Self::parse_address_list(address)? {
                    self.add_peer(&local_key, &ip_address, &key)?;
                    (other_key, Some(address.reinit_date), false)
                } else {
                    (other_key, None, false)
                }
            } else {
                (other_key, None, false)
            }
        } else if let Some(id) = &packet.from_short {
            (KeyId::from_data(id.id.as_slice().clone()), None, true)
        } else {
            fail!("No other key data inside packet: {:?}", packet)
        };
        let dst_reinit_date = &packet.dst_reinit_date;
        let reinit_date = &packet.reinit_date;
        if dst_reinit_date.is_some() != reinit_date.is_some() {
            fail!("Destination and source reinit dates mismatch")
        }
        if let Some(reinit_date) = reinit_date {
            if let Some(addr_reinit_date) = &address_reinit_date {
                if addr_reinit_date != reinit_date {
                    fail!("Address and source reinit dates mismatch")
                }
                address_reinit_date = None
            }
        }
        let peers = self.peers(&local_key)?;
        let peer = if let Some(channel) = channel {
            peers.map_of.get(&channel.other_key)
        } else {
            peers.map_of.get(&ret) 
        };
        let peer = if let Some(peer) = peer {
            peer
        } else {
            fail!("Unknown peer {}", ret)
        };
        let peer = peer.val();
        if check {
            check_signature(packet, &peer.address.key, false)?
        }
        if let (Some(dst_reinit_date), Some(reinit_date)) = (dst_reinit_date, reinit_date) {
            let local_reinit_date = peer.recv_state.reinit_date();
            let cmp_dst = dst_reinit_date.cmp(&local_reinit_date);
            if let Ordering::Greater = cmp_dst {
                fail!(
                    "Destination reinit date is too new: {} vs {}, {:?}", 
                    dst_reinit_date,
                    local_reinit_date,  
                    packet
                )
            }
            if *reinit_date > Version::get() + Self::CLOCK_TOLERANCE_SEC {
                fail!("Source reinit date is too new: {}", reinit_date)
            }
            let other_reinit_date = peer.send_state.reinit_date();
            if !peer.try_reinit(*reinit_date).await? {
                fail!("Source reinit date is too old: {}", reinit_date)
            }
/*
            let other_reinit_date = peer.send_state.reinit_date();
            match reinit_date.cmp(&other_reinit_date) {
                Ordering::Equal => (),
                Ordering::Greater => {
                    // Refresh reinit state
                    peer.send_state.reset_reinit_date(*reinit_date);
                    if other_reinit_date != 0 {
                        peer.send_state.reset_seqno().await?;
                        peer.recv_state.reset_seqno().await?;
                    }
                },
                Ordering::Less => if *reinit_date != 0 {
                    fail!("Source reinit date is too old: {}", reinit_date)
                }
            }
*/
            if *dst_reinit_date != 0 {
                if let Ordering::Less = cmp_dst {
                    // Push peer to refresh reinit date
                    self.send_message_to_peer(
                        TaggedAdnlMessage {
                            object: AdnlMessage::Adnl_Message_Nop,
                            #[cfg(feature = "telemetry")]
                            tag: 0x80000000 // Service message, tag is not important
                        },
                        &AdnlPeers::with_keys(local_key.clone(), ret.clone()),
                        false,
                    )?;
                    fail!(
                        "Destination reinit date is too old: {} vs {}, {:?}", 
                        dst_reinit_date, 
                        other_reinit_date,  
                        packet
                    )
                }
            }
/*            
            if dst_reinit_date != &0 {
                match dst_reinit_date.cmp(&peer.recv_state.reinit_date()) {
                    Ordering::Equal => (),                                                                                                               
                    Ordering::Greater => 
                        fail!("Destination reinit date is too new: {} vs {}, {:?}", 
                            dst_reinit_date,
                            peer.recv_state.reinit_date(),  
                            packet
                        ),
                    Ordering::Less => {
                        // Push peer to refresh reinit date
                        self.send_message_to_peer(
                            TaggedAdnlMessage {
                                object: AdnlMessage::Adnl_Message_Nop,
                                #[cfg(feature = "telemetry")]
                                tag: 0x80000000 // Service message, tag is not important
                            },
                            &AdnlPeers::with_keys(local_key.clone(), ret.clone()),
                            false,
                        )?;
                        fail!(
                            "Destination reinit date is too old: {} vs {}, {:?}", 
                            dst_reinit_date, 
                            peer.recv_state.reinit_date(),  
                            packet
                        )
                    }
                }
            }
            let other_reinit_date = peer.send_state.reinit_date();
            match reinit_date.cmp(&other_reinit_date) {
                Ordering::Equal => (),
                Ordering::Greater => if *reinit_date > Version::get() + Self::CLOCK_TOLERANCE_SEC {
                    fail!("Source reinit date is too new: {}", reinit_date)
                } else {
                    peer.send_state.reset_reinit_date(*reinit_date);
                    if other_reinit_date != 0 {
                        peer.send_state.reset_seqno().await?;
                        peer.recv_state.reset_seqno().await?;
                    }
                },
                Ordering::Less => 
                    fail!("Source reinit date is too old: {}", reinit_date)
            }
*/
        }
        if let Some(address_reinit_date) = address_reinit_date {
            if !peer.try_reinit(address_reinit_date).await? {
                log::warn!(
                    target: TARGET, 
                    "Address list reinit date is too old: {}",
                    address_reinit_date
                )
            }
        }
        if let Some(seqno) = &packet.seqno {
            match peer.recv_state.save_seqno(*seqno as u64, priority).await {
                Err(e) => fail!(
                    "Peer {} ({:?}): {}", 
                    ret, channel.map(|ch| ch.other_key.clone()), e
                ),
                Ok(false) => return Ok(None),
                _ => ()
            }
        }
        log::trace!(
            target: TARGET,
            "recv packet {} -> {} {:?}, seqno S{} R{}, priority {}",
            peer.address.key.id(), local_key, packet.seqno, 
            peer.send_state.seqno(priority),
            peer.recv_state.seqno(priority),
            priority
        );
        if let Some(seqno) = &packet.confirm_seqno {
            let local_seqno = peer.send_state.seqno(priority);
            if *seqno as u64 > local_seqno {
                fail!(
                    "Peer {}: too new ADNL packet seqno confirmed: {}, expected <= {}, {}", 
                    ret,
                    seqno, 
                    local_seqno,
                    priority
                )
            }
        }
        Ok(Some(ret))	
    }

    fn create_channel(
        &self, 
        peers: &AdnlPeers, 
        local_pub: &mut Option<[u8; 32]>,
        other_pub: &[u8; 32],
        context: &str
    ) -> Result<Arc<AdnlChannel>> {
        let local_key = peers.local();
        let other_key = peers.other();
        let peer = self.peers(local_key)?; 
        let peer = if let Some(peer) = peer.map_of.get(other_key) {
            peer
        } else {
            fail!("Channel {} with unknown peer {} -> {}", context, local_key, other_key)
        };
        let local_pvt_key = &peer.val().address.channel_key;
        let local_pub_key = local_pvt_key.pub_key()?;
        if let Some(ref local_pub) = local_pub {
            if local_pub_key != local_pub {
                fail!(
                    "Mismatch in key for channel {}\n{} / {}",
                    context,
                    base64::encode(local_pub_key), 
                    base64::encode(other_pub)
                )
            }
        } else {
            local_pub.replace(local_pub_key.try_into()?);
        }
        let channel = AdnlChannel::with_keys(
            local_key, 
            local_pvt_key, 
            other_key, 
            other_pub,
            self.allocated.channels.clone()
        )?;
        #[cfg(feature = "telemetry")]
        self.telemetry.allocated.channels.update( 
            self.allocated.channels.load(atomic::Ordering::Relaxed)
        );
        log::debug!(target: TARGET, "Channel {}: {} -> {}", context, local_key, other_key);
        log::trace!(
            target: TARGET,
            "Channel send ID {}, recv ID {}", 
            base64::encode(channel.ordinary_send_id()),
            base64::encode(channel.ordinary_recv_id())
        );
        Ok(Arc::new(channel))
    }

    fn decrypt_packet_from_channel(
        &self, 
        buf: &mut Vec<u8>,
        channel: &Arc<AdnlChannel>,
        priority: bool
    ) -> Result<()> {
        if priority {
            channel.decrypt_priority(buf)?
        } else {
            channel.decrypt_ordinary(buf)?
        }
        // Ensure both sides of channel established
        if channel.flags.load(atomic::Ordering::Relaxed) & AdnlChannel::ESTABLISHED == 0 {
            let peers = self.peers(&channel.local_key)?;
            if let Some(removed) = peers.channels_wait.remove(&channel.other_key) {
                let result = peers.channels_send.reinsert(removed);
                if let lockfree::map::Insertion::Failed(_) = result {
                    fail!("Internal error when register send channel");
                }
            }
        }
        // Restore channel health 
        channel.flags.store(
            AdnlChannel::ESTABLISHED | AdnlChannel::SEQNO_RESET, 
            atomic::Ordering::Relaxed
        );
        Ok(())
    }

    fn drop_receive_subchannels(
        &self, 
        channel: &Arc<AdnlChannel>
    ) -> Option<lockfree::map::Removed<ChannelId, Subchannel>> {
        self.channels_recv.remove(channel.ordinary_recv_id());
        self.channels_recv.remove(channel.priority_recv_id())
    }

    fn gen_rand() -> Vec<u8> {  
        const RAND_SIZE: usize = 16;
        let mut ret = Vec::with_capacity(RAND_SIZE);
        ret.resize(RAND_SIZE, 0);
        rand::thread_rng().fill(&mut ret[..]);
        ret
    }

    async fn graceful_close<T>(mut reader: tokio::sync::mpsc::UnboundedReceiver<T>) {
        reader.close();
        while let Some(_) = reader.recv().await {
        }
    }

    #[cfg(feature = "dump")]
    fn need_dump(pkt: &AdnlPacketContents) -> bool {
        if let Some(msg) = pkt.message.as_ref() {
            match msg {
                AdnlMessage::Adnl_Message_Custom(_) => false,
                AdnlMessage::Adnl_Message_Nop => false,
                _ => true
            }
        } else if let Some(msgs) = pkt.messages.as_ref() {
            for msg in msgs.0.iter() {
                match msg {
                    AdnlMessage::Adnl_Message_Custom(_) => (),
                    AdnlMessage::Adnl_Message_Nop => (),
                    _ => return true
                }
            }
            false
        } else {
            false
        }
    }

    fn peers(&self, src: &Arc<KeyId>) -> Result<Arc<Peers>> {
        if let Some(peers) = self.peers.get(src) {
            Ok(peers.val().clone())
        } else {
            fail!("Cannot get peers list for unknown local key {}", src)
        }
    }

    async fn process_message(
        &self,
        subscribers: &Vec<Arc<dyn Subscriber>>,
        msg: AdnlMessage,
        peers: &AdnlPeers,
        priority: bool
    ) -> Result<()> {
        log::trace!(target: TARGET, "Process message {:?}", msg);
        let new_msg = if let AdnlMessage::Adnl_Message_Part(part) = &msg {
            let transfer_id = part.hash.as_slice();
            let added = add_counted_object_to_map(
                &self.transfers,
                transfer_id.clone(),
                || {
                    let transfer = Transfer {
                        data: lockfree::map::Map::new(),
                        received: AtomicUsize::new(0),
                        total: part.total_size as usize,
                        updated: UpdatedAt::new(),
                        counter: self.allocated.transfers.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    self.telemetry.allocated.transfers.update(
                        self.allocated.transfers.load(atomic::Ordering::Relaxed)
                    );
                    Ok(Arc::new(transfer))
                }
            )?;
            if let Some(transfer) = self.transfers.get(transfer_id) {
                if added {
                    let transfers_wait = self.transfers.clone();
                    let transfer_wait = transfer.val().clone();
                    let transfer_id_wait = transfer_id.clone();
                    tokio::spawn(
                        async move {
                            loop {
                                tokio::time::sleep(
                                    Duration::from_millis(Self::TIMEOUT_TRANSFER_SEC * 100)
                                ).await;
                                if transfer_wait.updated.is_expired(Self::TIMEOUT_TRANSFER_SEC) {
                                    if transfers_wait.remove(&transfer_id_wait).is_some() {
                                        log::info!(
                                            target: TARGET, 
                                            "ADNL transfer {} timed out",
                                            base64::encode(&transfer_id_wait)
                                        );
                                    }
                                    break
                                }
                            }
                        }
                    );
                }
                let transfer = transfer.val();
                transfer.updated.refresh();
                transfer.data.insert(part.offset as usize, part.data.to_vec());
                transfer.received.fetch_add(part.data.len(), atomic::Ordering::Relaxed);
                match Self::update_transfer(transfer_id, transfer) {
                    Ok(Some(msg)) => {
                        self.transfers.remove(transfer_id);
                        Some(msg)
                    },
                    Err(error) => {
                        self.transfers.remove(transfer_id);
                        return Err(error)
                    },
                    _ => return Ok(())
                }
            } else {
                fail!("INTERNAL ERROR: cannot find ADNL transfer")
            }
        } else {
            None
        };
        let msg = match new_msg.as_ref().unwrap_or(&msg) {
            AdnlMessage::Adnl_Message_Answer(answer) => {
                self.process_answer(&answer, peers.other()).await?;
                None
            },
            AdnlMessage::Adnl_Message_ConfirmChannel(confirm) => {
                let mut local_pub = Some(confirm.peer_key.as_slice().clone());
                let channel = self.create_channel(
                    peers, 
                    &mut local_pub, 
                    confirm.key.as_slice(), 
                    "confirmation"
                )?;
                /*
                self.channels_send.insert(peers.other().clone(), channel.clone());
log::warn!(target: TARGET, "On recv confirm channel in {}", channel.local_key);
                self.add_receive_subchannels(channel).await?;
                */
                self.add_subchannels(channel, false).await?;
                None
            },
            AdnlMessage::Adnl_Message_CreateChannel(create) => {
                let mut local_pub = None;
                let channel = self.create_channel(
                    peers, 
                    &mut local_pub, 
                    create.key.as_slice(), 
                    "creation"
                )?;
                let msg = if let Some(local_pub) = local_pub {
                    ConfirmChannel {
                        key: UInt256::with_array(local_pub),
                        peer_key: create.key,
                        date: create.date
                    }.into_boxed()
                } else {
                    fail!("INTERNAL ERROR: local key mismatch in channel creation")
                };
/*
                self.channels_wait
                    .insert(peers.other().clone(), channel.clone())
                    .or(self.channels_send.remove(peers.other()))
                    .and_then(|removed| self.drop_receive_subchannels(removed.val()));
log::warn!(target: TARGET, "On recv create channel in {}", channel.local_key);
                self.add_receive_subchannels(channel).await?;
*/
                self.add_subchannels(channel, true).await?;
                Some(
                    TaggedAdnlMessage {
                        object: msg,
                        #[cfg(feature = "telemetry")]
                        tag: 0x80000000 // Service message, tag is not important
                    }
                )
            },
            AdnlMessage::Adnl_Message_Custom(custom) => {
                if !Query::process_custom(subscribers, &custom, peers).await? {
                    fail!("No subscribers for custom message {:?}", custom)
                }
                None
            },
            AdnlMessage::Adnl_Message_Nop => None,
            AdnlMessage::Adnl_Message_Query(query) => {
                Self::process_query(subscribers, &query, peers).await?
            },
            _ => fail!("Unsupported ADNL message {:?}", msg)
        };
        if let Some(msg) = msg {
            let (_, repeat) = self.send_message_to_peer(msg, peers, priority)?;
            if priority {
                if let MessageRepeat::NotNeeded = &repeat {
                    return Ok(())
                }
            } else { 
                if let MessageRepeat::Unapplicable = &repeat {
                    return Ok(())
                }
            }
            fail!("INTERNAL ERROR: bad repeat {:?} in answer to ADNL message", repeat)
        } else {
            Ok(())
        }
    }

    async fn process_answer(&self, answer: &AdnlAnswerMessage, src: &Arc<KeyId>) -> Result<()> {
        let query_id = answer.query_id.as_slice().clone();
        if !Self::update_query(&self.queries, query_id, Some(&answer.answer)).await? {
            fail!("Received answer from {} to unknown query {:?}", src, answer)
        }
        Ok(())
    }

    async fn process_query(
        subscribers: &Vec<Arc<dyn Subscriber>>,
        query: &AdnlQueryMessage,
        peers: &AdnlPeers
    ) -> Result<Option<TaggedAdnlMessage>> {
        let query_id = query.query_id.as_slice();
        log::info!(
            target: TARGET_QUERY, 
            "Recv query {:02x}{:02x}{:02x}{:02x}", 
            query_id[0], query_id[1], query_id[2], query_id[3]
        );
        if let (true, answer) = Query::process_adnl(subscribers, query, peers).await? {
            log::info!(
                target: TARGET_QUERY, 
                "Reply to query {:02x}{:02x}{:02x}{:02x}", 
                query_id[0], query_id[1], query_id[2], query_id[3]
            );
            Ok(answer)
        } else {
            fail!("No subscribers for query {:?}", query)
        }
    }

    fn process_query_result(
        &self, 
        context: Arc<QuerySendContext>, 
        peers: &AdnlPeers
    ) -> Result<Option<TLObject>> {
        log::info!(
            target: TARGET_QUERY, 
            "Finished query {:02x}{:02x}{:02x}{:02x}", 
            context.query_id[0], context.query_id[1], context.query_id[2], context.query_id[3]
        );
        if let Some(removed) = self.queries.remove(&context.query_id) {
            match removed.val() {
                Query::Received(answer) => 
                    return Ok(Some(deserialize_boxed(answer)?)),
                Query::Timeout => if let MessageRepeat::Required = context.repeat {
                    return Ok(None)
                } else {
                    /* Monitor channel health */
                    if let Some(channel) = &context.channel {
                        let flags = AdnlChannel::ESTABLISHED | AdnlChannel::SEQNO_RESET;
                        let now = Version::get() as u64;
                        let was = channel.flags.compare_exchange(
                            flags,
                            flags | (now + Self::TIMEOUT_CHANNEL_RESET_SEC),
                            atomic::Ordering::Relaxed,
                            atomic::Ordering::Relaxed
                        ).unwrap_or_else(|was| was);
                        let was = was & !AdnlChannel::ESTABLISHED;
                        if (was > 0) && (was < now as u64) {
                            self.reset_peers(&peers)? 
                        }
                    }
                    return Ok(None)
                },
                _ => ()
            }
        }
        fail!(
            "INTERNAL ERROR: ADNL query {:02x}{:02x}{:02x}{:02x} mismatch",
            context.query_id[0], context.query_id[1], context.query_id[2], context.query_id[3]
        )
    }

    async fn process_packet(
        &self, 
        packet: &mut PacketBuffer,
        subchannel: Subchannel,
        subscribers: &Vec<Arc<dyn Subscriber>>,
    ) -> Result<()> {
        #[cfg(feature = "telemetry")]
        let received_len = packet.buf.len();
#[cfg(feature = "debug")]
println!("RECV {}", received_len);
        let (priority, local_key, channel) = match &subchannel {
            Subchannel::None => if let Some(local_key) = AdnlHandshake::parse_packet(
                &self.config.keys, 
                &mut packet.buf, 
                None
            )? {
                (false, local_key, None)
            } else {
                log::trace!(
                    target: TARGET,
                    "Received message to unknown key ID {}", 
                    base64::encode(&packet.buf[0..32])
                );
                #[cfg(feature = "telemetry")]
                self.telemetry.ordinary.proc_unknown.update(1);
                return Ok(())
            },
            Subchannel::Ordinary(channel) => {
                self.decrypt_packet_from_channel(&mut packet.buf, &channel, false)?;
                (false, channel.local_key.clone(), Some(channel))
            },
            Subchannel::Priority(channel) => {
                self.decrypt_packet_from_channel(&mut packet.buf, &channel, true)?;
                (true, channel.local_key.clone(), Some(channel))
            }
        };
        let pkt = deserialize_boxed(&packet.buf[..])?
            .downcast::<AdnlPacketContentsBoxed>()
            .map_err(|pkt| error!("Unsupported ADNL packet format {:?}", pkt))?
            .only();
        let other_key = if let Some(key) = self.check_packet(
            &pkt, 
            priority, 
            &local_key, 
            channel
        ).await? {
            key
        } else {
            #[cfg(feature = "telemetry")]
            if priority {
                self.telemetry.priority.proc_invalid.update(1)
            } else {
                self.telemetry.ordinary.proc_invalid.update(1)
            }
            return Ok(())
        };
        #[cfg(feature = "dump")]
        if Self::need_dump(&pkt) {
            if let Some(dump) = self.dump.as_ref() {
                let msg = format!(
                    "{} Recv packet, priority {}\n{:?}\nDump\n{}", 
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    priority, 
                    pkt, 
                    dump!(&packet.buf[..])
                );
                dump.sender.send(
                    DumpRecord {
                        alive: true,
                        key_id: other_key.clone(),
                        msg
                    }
                )?;
            }
        }
        let peers = Arc::new(AdnlPeers::with_keys(local_key, other_key));
        #[cfg(feature = "telemetry")]
        if let Some(peer) = self.peers(peers.local())?.map_of.get(peers.other()) {
            peer.val().update_recv_stats(received_len as u64, peers.local())
        }
        if let Some(msg) = pkt.message { 
            #[cfg(feature = "telemetry")]
            let chk = self.telemetry.add_check(Telemetry::get_message_info(&msg))?;
            let res = self.process_message(
                subscribers, 
                msg, 
                &peers,
                priority
            ).await;
            #[cfg(feature = "telemetry")]
            self.telemetry.drop_check(chk);
            res
        } else if let Some(msgs) = pkt.messages {
            let mut res = Ok(());
            for msg in msgs.0 {
                #[cfg(feature = "telemetry")]
                let chk = self.telemetry.add_check(Telemetry::get_message_info(&msg))?;
                res = self.process_message(
                    subscribers, 
                    msg,
                    &peers,
                    priority
                ).await;
                #[cfg(feature = "telemetry")]
                self.telemetry.drop_check(chk);
                if res.is_err() {
                    break
                }
            }
            res 
        } else {
            // Specifics of implementation. 
            // Address/seqno update is to be sent serarately from data
            // fail!("ADNL packet ({}) without a message: {:?}", buf.len(), pkt)
            Ok(())
        }?;
        #[cfg(feature = "telemetry")]
        if priority {
            self.telemetry.priority.proc_success.update(1)
        } else {
            self.telemetry.ordinary.proc_success.update(1)
        }
        Ok(())
    }

    async fn send_query_with_priority(
        self: Arc<Self>, 
        prefix: Option<&[u8]>,
        query: &TaggedTlObject,
        peers: &AdnlPeers,
        timeout: Option<u64>,
        priority: bool
    ) -> Result<Arc<QuerySendContext>> {
        let (query_id, msg) = Query::build(prefix, &query)?;
        let (ping, query) = Query::new();
        self.queries.insert(query_id, query);
        log::info!(
            target: TARGET_QUERY, 
            "Send query {:02x}{:02x}{:02x}{:02x}", 
            query_id[0], query_id[1], query_id[2], query_id[3]
        );
        let (channel, repeat) = if peers.local() == peers.other() {       
            self.queue_send_loopback_packets.send((msg.object, peers.local().clone()))?;
            (None, MessageRepeat::Unapplicable)
        } else {
            self.send_message_to_peer(msg, &peers, priority)?
        };
        self.queue_monitor_queries.push(
            (timeout.unwrap_or(Self::TIMEOUT_QUERY_MAX_MS), query_id)
        );
        let ret = QuerySendContext {
            channel, 
            query_id,
            repeat,
            reply_ping: ping
        };
        Ok(Arc::new(ret))
    }

    fn send_message_to_peer(
        &self, 
        msg: TaggedAdnlMessage, 
        peers: &AdnlPeers, 
        priority: bool
    ) -> Result<(Option<Arc<AdnlChannel>>, MessageRepeat)> {

        const SIZE_ANSWER_MSG: usize          = 44;
        const SIZE_CONFIRM_CHANNEL_MSG: usize = 72;
        const SIZE_CREATE_CHANNEL_MSG: usize  = 40;
        const SIZE_CUSTOM_MSG: usize          = 12;
        const SIZE_NOP_MSG: usize             =  4;
        const SIZE_QUERY_MSG: usize           = 44;

        fn build_part_message(
            data: &[u8], 
            hash: &[u8; 32],
            offset: &mut usize, 
            max_size: usize
        ) -> AdnlMessage {
            let mut part = Vec::new();
            let next = min(data.len(), *offset + max_size);
            part.extend_from_slice(&data[*offset..next]);
            let ret = AdnlPartMessage {
                hash: UInt256::with_array(hash.clone()),
                total_size: data.len() as i32,
                offset: *offset as i32,
                data: ton::bytes(part)
            }.into_boxed();
            *offset = next;
            ret
        }

        log::trace!(target: TARGET, "Send message {:?}", msg.object);

        let src = self.key_by_id(peers.local())?;
        let dst = peers.other();
        let peers = self.peers(peers.local())?;
        let peer = if let Some(peer) = peers.map_of.get(dst) {
            peer
        } else {
            fail!("Unknown peer {}", dst)
        };
        let peer = peer.val();
        let channel = peers.channels_send.get(dst).map(|guard| guard.val().clone());

        let create_channel_msg = if channel.is_none() && peers.channels_wait.get(dst).is_none() {
            log::debug!(target: TARGET, "Create channel {} -> {}", src.id(), dst);
            let pub_key = peer.address.channel_key.pub_key()?;
            Some(
                CreateChannel {
                    key: UInt256::with_array(pub_key.try_into()?),
                    date: Version::get()
                }.into_boxed()
            )
        } else {
            None
        };
        let mut size = if create_channel_msg.is_some() {
            SIZE_CREATE_CHANNEL_MSG
        } else {
            0
        };
        size += match &msg.object {
            AdnlMessage::Adnl_Message_Answer(answer) => answer.answer.len() + SIZE_ANSWER_MSG,
            AdnlMessage::Adnl_Message_ConfirmChannel(_) => SIZE_CONFIRM_CHANNEL_MSG,
            AdnlMessage::Adnl_Message_Custom(custom) => custom.data.len() + SIZE_CUSTOM_MSG,
            AdnlMessage::Adnl_Message_Nop => SIZE_NOP_MSG,
            AdnlMessage::Adnl_Message_Query(query) => query.query.len() + SIZE_QUERY_MSG,
            _ => fail!("Unexpected message to send {:?}", msg.object)  
        };

        let repeat = if size <= Self::MAX_ADNL_MESSAGE {
            if let Some(create_channel_msg) = create_channel_msg {
                log::trace!(target: TARGET, "Send with message {:?}", create_channel_msg);
                self.send_packet(
                    peer, 
                    &src, 
                    channel.as_ref(), 
                    None, 
                    Some(vec![create_channel_msg, msg.object]),
                    priority,
                    #[cfg(feature = "telemetry")]
                    msg.tag
                )?
            } else {
                self.send_packet(
                    peer, 
                    &src, 
                    channel.as_ref(), 
                    Some(msg.object), 
                    None, 
                    priority,
                    #[cfg(feature = "telemetry")]
                    msg.tag
                )?
            }
        } else {
            let data = serialize_boxed(&msg.object)?;
            let hash = sha256_digest(&data);
            let mut offset = 0;
            let mut repeat = if let Some(create_channel_msg) = create_channel_msg {
                let part_msg = build_part_message(
                    &data[..],
                    &hash,
                    &mut offset, 
                    Self::MAX_ADNL_MESSAGE - SIZE_CREATE_CHANNEL_MSG
                );
                self.send_packet(
                    peer, 
                    &src, 
                    channel.as_ref(), 
                    None, 
                    Some(vec![create_channel_msg, part_msg]),
                    priority,
                    #[cfg(feature = "telemetry")]
                    msg.tag
                )?
            } else {
                MessageRepeat::Unapplicable
            };
            while offset < data.len() {
                let part_msg = build_part_message(
                    &data[..], 
                    &hash,
                    &mut offset, 
                    Self::MAX_ADNL_MESSAGE
                );
                let upd = self.send_packet(
                    peer, 
                    &src, 
                    channel.as_ref(), 
                    Some(part_msg), 
                    None, 
                    priority,
                    #[cfg(feature = "telemetry")]
                    msg.tag
                )?;
                if let MessageRepeat::Unapplicable = &repeat {
                    repeat = upd
                } else if repeat != upd {
                    fail!("INTERNAL ERROR: bad repeat in ADNL message part")
                }
            };
            repeat
        };
        Ok((channel, repeat))

    }

    fn send_packet(
        &self, 
        peer: &Peer,
        source: &Arc<dyn KeyOption>,
        channel: Option<&Arc<AdnlChannel>>, 
        message: Option<AdnlMessage>, 
        messages: Option<Vec<AdnlMessage>>,
        mut priority: bool,
        #[cfg(feature = "telemetry")]
        tag: u32
    ) -> Result<MessageRepeat> {
        let repeat = if priority {
            // Decide whether we need priority traffic
            if channel.is_none() {
                // No need if no channel 
                priority = false
            } else  {
                // No need if no priority replies
                if peer.recv_state.seqno(true) == 0 {
                    if peer.send_state.seqno(true) > Self::MAX_PRIORITY_ATTEMPTS {
                        priority = false
                    }
                }
            }
            if priority && (peer.recv_state.seqno(priority) == 0) {
                MessageRepeat::Required
            } else {
                MessageRepeat::NotNeeded
            }
        } else {
            MessageRepeat::Unapplicable
        };
        let mut pkt = AdnlPacketContents {
            rand1: ton::bytes(Self::gen_rand()),
            from: if channel.is_some() {
                None
            } else {
                Some(source.into_public_key_tl()?)
            },
            from_short: if channel.is_some() {
                None
            } else {
                Some(
                    AdnlIdShort {
                        id: UInt256::with_array(source.id().data().clone())
                    }
                )
            }, 
            message,
            messages: if let Some(messages) = messages {
                Some(messages.into())
            } else {
                None
            },
            address: Some(
                self.build_address_list(Some(Version::get() + Self::TIMEOUT_ADDRESS_SEC))?
            ),
            priority_address: None,
            seqno: Some(peer.send_state.next_seqno(priority) as i64),
            confirm_seqno: Some(peer.recv_state.seqno(priority) as i64),
            recv_addr_list_version: None,
            recv_priority_addr_list_version: None,
            reinit_date: if channel.is_some() {
                None
            } else {
                Some(peer.recv_state.reinit_date())
            },
            dst_reinit_date: if channel.is_some() {
                None
            } else {
                Some(peer.send_state.reinit_date())
            },
            signature: None,
            rand2: ton::bytes(Self::gen_rand())
        };
        if channel.is_none() {
            let signature = source.sign(&serialize_boxed(&pkt.clone().into_boxed())?)?;
            pkt.signature = Some(ton::bytes(signature.to_vec()));
        }
        #[cfg(feature = "dump")]
        let msg = if Self::need_dump(&pkt) && self.dump.is_some() {
            Some(format!("Send packet, priority {}\n{:?}", priority, pkt))
        } else {
            None
        };
        let mut data = serialize_boxed(&pkt.into_boxed())?;
        #[cfg(feature = "dump")]
        if let Some(msg) = msg {
            if let Some(dump) = self.dump.as_ref() {
                let msg = format!(
                    "{} {}\nDump\n{}", 
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    msg, 
                    dump!(&data[..])
                );
                dump.sender.send(
                    DumpRecord {
                        alive: channel.is_some(),
                        key_id: peer.address.key.id().clone(), 
                        msg
                    }
                )?;
            }
        }
        if let Some(channel) = channel {
            if priority {
                channel.encrypt_priority(&mut data)?;
            } else {
                channel.encrypt_ordinary(&mut data)?;
            }
        } else {
            let key = Ed25519KeyOption::generate()? as Arc<dyn KeyOption>;
            AdnlHandshake::build_packet(&mut data, &key, &peer.address.key)?;
        }
        log::trace!(
            target: TARGET,
            "send packet {} -> {}, seqno S{} R{}, priority {}",
            source.id(), peer.address.key.id(), 
            peer.send_state.seqno(priority),
            peer.recv_state.seqno(priority),
            priority
        );
        #[cfg(feature = "telemetry")]
        peer.update_send_stats(data.len() as u64, source.id());
        #[cfg(feature = "telemetry")]
        if !priority {
            loop {
                if let Some(metric) = self.telemetry.ordinary.send_tags.get(&tag) {
                    metric.val().update(1);
                    break
                }
                let name = format!("Send ordinary {:08x}", tag);
                let metric = Telemetry::create_metric_builder(name.as_str());
                let added = add_unbound_object_to_map(
                    &self.telemetry.ordinary.send_tags,
                    tag,
                    || Ok(metric.clone())
                )?;
                if added {
                    self.telemetry.printer.add_metric(TelemetryItem::MetricBuilder(metric))
                }
            }
        }
        let job = SendData { 
            destination: peer.address.ip_address.load(atomic::Ordering::Relaxed),
            data
        };
        if priority {
            self.send_pipeline.put_priority(SendJob::Data(job))
        } else {
            self.send_pipeline.put_ordinary(SendJob::Data(job))
        }
        Ok(repeat)
    }

    async fn update_query(
        queries: &Arc<QueryCache>, 
        query_id: QueryId,
        answer: Option<&ton::bytes>
    ) -> Result<bool> {
        let insertion = queries.insert_with(
            query_id, 
            |_, inserted, found| {
                if let Some(&(_, Query::Sent(_))) = found {
                    lockfree::map::Preview::New(
                        if let Some(answer) = answer {
                            Query::Received(answer.to_vec())
                        } else {
                            Query::Timeout
                        }
                    ) 
                } else if inserted.is_none() {
                    lockfree::map::Preview::Discard
                } else {
                    lockfree::map::Preview::Keep
                }
            }
        );
        let removed = if let Some(removed) = insertion.updated() {
            removed
        } else {
            return Ok(false);
        };
        if let Query::Sent(pong) = removed.val() {
            pong.wait().await;
        } else {
            fail!(
                "INTERNAL ERROR: ADNL query state mismatch, \
                 expected Query::Sent, found {:?}",
                removed.val() 
            )   
        }
        Ok(true)
    }

    fn update_transfer(
        transfer_id: &TransferId, 
        transfer: &Transfer
    ) -> Result<Option<AdnlMessage>> {
        let mut received = transfer.received.compare_exchange(
            transfer.total, 
            2 * transfer.total, 
            atomic::Ordering::Relaxed,
            atomic::Ordering::Relaxed
        ).unwrap_or_else(|was| was);
        if received > transfer.total {
            if received == 2 * transfer.total {
                // It seems we finished transfer in neighbour thread
                return Ok(None)
            }
            fail!(
                "Invalid ADNL part transfer: size mismatch {} vs. total {}",
                received,
                transfer.total
            )
        }
        if received == transfer.total {
            log::debug!("Finished ADNL part {} (total {})", received, transfer.total);
            received = 0;
            let mut buf = Vec::with_capacity(transfer.total);
            while received < transfer.total {
                if let Some(data) = transfer.data.get(&received) {
                    let data = data.val();
                    received += data.len();
                    buf.extend_from_slice(&data)
                } else {   
                    fail!("Invalid ADNL part transfer: parts mismatch")
                }
            }
            if !sha256_digest(&buf).eq(transfer_id) {
                fail!("Bad hash of ADNL transfer {}", base64::encode(transfer_id))
            }
            let msg = deserialize_boxed(&buf)?
                .downcast::<AdnlMessage>()
                .map_err(|msg| error!("Unsupported ADNL messge {:?}", msg))?;
            Ok(Some(msg))
        } else {
            log::debug!("Received ADNL part {} (total {})", received, transfer.total);
            Ok(None)
        }
    }

}
