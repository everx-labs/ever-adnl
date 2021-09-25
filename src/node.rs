use crate::{
    declare_counted, from_slice, 
    common::{
        add_counted_object_to_map, add_counted_object_to_map_with_update, 
        add_unbound_object_to_map, add_unbound_object_to_map_with_update, 
        AdnlCryptoUtils, AdnlHandshake, AdnlPeers, AdnlPingSubscriber, deserialize, get256, 
        hash, CountedObject, Counter, KeyId, KeyOption, KeyOptionJson, Query, QueryCache, 
        QueryId, serialize, Subscriber, TARGET, TaggedAdnlMessage, TaggedByteSlice, 
        TaggedTlObject, UpdatedAt, Version
    }
};
#[cfg(feature = "telemetry")]
use crate::{
    common::tag_from_data, 
    telemetry::{Metric, MetricBuilder, TelemetryItem, TelemetryPrinter}
};
use aes_ctr::cipher::stream::SyncStreamCipher;
use rand::Rng;
use sha2::Digest;
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    cmp::{max, min, Ordering}, collections::VecDeque, fmt::{self, Debug, Display, Formatter}, 
    io::ErrorKind, net::{IpAddr, Ipv4Addr, SocketAddr}, 
    sync::{Arc, Condvar, Mutex, atomic::{self, AtomicI32, AtomicU32, AtomicU64, AtomicUsize}},
    time::{Duration, Instant}, thread
};
#[cfg(feature = "compression")]
use std::io::Cursor;
use ton_api::{
    IntoBoxed, 
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
use ton_types::{error, fail, Result};

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
        channel_pvt_key: &Arc<KeyOption>, 
        other_key: &Arc<KeyId>,
        channel_pub_key: &[u8; 32],
        counter: Arc<AtomicU64>
    ) -> Result<Self> {
        let fwd_secret = AdnlCryptoUtils::calc_shared_secret(
            channel_pvt_key.pvt_key()?, 
            channel_pub_key
        );
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
            key: ton::int256(secret.clone())
        };
        hash(object)
    }

    fn decrypt(buf: &mut Vec<u8>, side: &SubchannelSide) -> Result<()> {
        if buf.len() < 64 {
            fail!("Channel message is too short: {}", buf.len())
        }
        Self::process_data(buf, &side.secret);
        if !sha2::Sha256::digest(&buf[64..]).as_slice().eq(&buf[32..64]) {
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
        let checksum = {
            let checksum = sha2::Sha256::digest(&buf[..]);
            let checksum = checksum.as_slice();
            from_slice!(checksum, 32)
        };
        let len = buf.len();
        buf.resize(len + 64, 0);
        buf[..].copy_within(..len, 64);                                                         
        buf[..32].copy_from_slice(&side.id);
        buf[32..64].copy_from_slice(&checksum[..]);
        Self::process_data(buf, &side.secret);
        Ok(())
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

    fn process_data(buf: &mut Vec<u8>, secret: &[u8; 32]) {
        let digest = &buf[32..64];
        let mut key = from_slice!(secret, 0, 16, digest, 16, 16);
        let mut ctr = from_slice!(digest, 0,  4, secret, 20, 12);
        AdnlCryptoUtils::build_cipher_secure(&mut key[..], &mut ctr[..])
            .apply_keystream(&mut buf[64..]);
    }
  
}

struct AdnlNodeAddress {
    channel_key: Arc<KeyOption>,
    ip_address: AtomicU64,
    key: Arc<KeyOption>
}

impl AdnlNodeAddress {
    fn from_ip_address_and_key(ip_address: IpAddress, key: Arc<KeyOption>) -> Result<Self> {
        let (_, channel_key) = KeyOption::with_type_id(key.type_id())?;
        let ret = Self {
            channel_key: Arc::new(channel_key),
            ip_address: AtomicU64::new(ip_address.0),
            key
        };
        Ok(ret)
    }
}

/// ADNL node configuration
pub struct AdnlNodeConfig {
    ip_address: IpAddress,
    keys: lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>,
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
        IpAddress::from_string(&self.ip_address)
    }   

    /// Get key by tag
    pub fn key_by_tag(&self, tag: usize, as_src: bool) -> Result<KeyOption> {
        for key in self.keys.iter() {
            if key.tag == tag {
                return if as_src {
                    KeyOption::from_private_key(&key.data)
                } else {
                    KeyOption::from_public_key(&key.data)
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
        keys: Vec<(KeyOption, usize)>
    ) -> Result<Self> {
        let ret = AdnlNodeConfig {
            ip_address: IpAddress::from_string(ip_address)?,
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
        type_id: i32, 
        keytags: Vec<([u8; 32], usize)>
    ) -> Result<(AdnlNodeConfigJson, Self)> {
        let mut keys = Vec::new();
        for (key, tag) in keytags {
            let (json, key) = KeyOption::from_type_and_private_key(type_id, &key)?;
            keys.push((json, key, tag))
        }
        Self::create_configs(ip_address, keys)
    } 
   
    /// Construct from JSON data 
    pub fn from_json(json: &str, as_src: bool) -> Result<Self> {
        let json_config: AdnlNodeConfigJson = serde_json::from_str(json)?;
        Self::from_json_config(&json_config, as_src)
    }

    /// Construct from JSON config structure
    pub fn from_json_config(json_config: &AdnlNodeConfigJson, as_src: bool) -> Result<Self> {
        let ret = AdnlNodeConfig {
            ip_address: json_config.ip_address()?,
            keys: lockfree::map::Map::new(),
            tags: lockfree::map::Map::new(),
            recv_pipeline_pool: json_config.recv_pipeline_pool,
            recv_priority_pool: json_config.recv_priority_pool,
            throughput: json_config.throughput
        };
        for key in json_config.keys.iter() {
            let data = if as_src {
                KeyOption::from_private_key(&key.data)?
            } else {
                KeyOption::from_public_key(&key.data)?
            };
            ret.add_key(data, key.tag)?;
        }
        Ok(ret)
    }

    /// Construct with given IP address (new key pair will be generated)
    pub fn with_ip_address_and_key_type(
        ip_address: &str, 
        type_id: i32, 
        tags: Vec<usize>
    ) -> Result<(AdnlNodeConfigJson, Self)> {
        let mut keys = Vec::new();
        for tag in tags {
            let (json, key) = KeyOption::with_type_id(type_id)?;
            keys.push((json, key, tag))
        }
        Self::create_configs(ip_address, keys)
    }    

    /// Node IP address
    pub fn ip_address(&self) -> &IpAddress {
        &self.ip_address
    }

    /// Node key by ID
    pub fn key_by_id(&self, id: &Arc<KeyId>) -> Result<Arc<KeyOption>> {
        if let Some(key) = self.keys.get(id) {
            Ok(key.val().clone())
        } else {
            fail!("Bad key id {}", id)
        }
    }

    /// Node key by tag
    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<KeyOption>> {
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

    fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
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
            let key = Arc::new(key);
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
        keys: Vec<(KeyOptionJson, KeyOption, usize)>
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

#[cfg(feature = "compression")] 
pub struct DataCompression;

#[cfg(feature = "compression")] 
impl DataCompression {

    const COMPRESSION_LEVEL: i32 = 0;
    const SIZE_COMPRESSION_THRESHOLD: usize = 256;
    const TAG_COMPRESSED: u8 = 0x80;
    const TAG_UNCOMPRESSED: u8 = 0x00;
 
    pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
        let uncompressed = data.len();
        if uncompressed <= Self::SIZE_COMPRESSION_THRESHOLD {
            let mut ret = Vec::with_capacity(data.len() + 1);
            ret.extend_from_slice(data);  
            log::info!(target: TARGET, "Compression: {} sent as is", uncompressed);
            ret.push(Self::TAG_UNCOMPRESSED);
            Ok(ret)
        } else {
            let mut ret = zstd::stream::encode_all(Cursor::new(data), Self::COMPRESSION_LEVEL)?;
            let compressed = ret.len();
            log::info!(target: TARGET, "Compression: {} -> {}", uncompressed, compressed);
            ret.push(Self::TAG_COMPRESSED);
            Ok(ret)
        }
    } 

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        let len = data.len();
        if len == 0 {
            fail!("Too short input data for decompression")
        }
        match data[len - 1] {
            Self::TAG_COMPRESSED => 
                Ok(zstd::stream::decode_all(Cursor::new(&data[..len - 1]))?),
            Self::TAG_UNCOMPRESSED => 
                Ok(data[..len - 1].to_vec()),
            x => fail!("Bad compression tag {:x}", x) 
        }
    }

}

/// IP address internal representation
#[derive(PartialEq)]
pub struct IpAddress(u64);

impl IpAddress {

    /// Construct from string 
    pub fn from_string(src: &str) -> Result<Self> {
        let addr: SocketAddr = src.parse()?;
        if let IpAddr::V4(ip) = addr.ip() {
            Ok(Self::from_ip_and_port(u32::from_be_bytes(ip.octets()), addr.port()))
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

    fn from_ip_and_port(ip: u32, port: u16) -> Self {
        Self(((ip as u64) << 16) | port as u64)
    }
    fn ip(&self) -> u32 {
        let Self(ref ip) = self;
        (*ip >> 16) as u32
    }
    fn port(&self) -> u16 {
        let Self(ref ip) = self;
        *ip as u16
    }
    fn set_ip(&mut self, new_ip: u32) {
        let Self(ref mut ip) = self;
        *ip = ((new_ip as u64) << 16) | (*ip & 0xFFFF)
    }
    fn set_port(&mut self, new_port: u16) {
        let Self(ref mut ip) = self;
        *ip = (*ip & 0xFFFFFFFF0000u64) | new_port as u64
    }

}

impl Debug for IpAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for IpAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f, 
            "{}.{}.{}.{}:{}", 
            (self.0 >> 40) as u8,
            (self.0 >> 32) as u8,
            (self.0 >> 24) as u8,
            (self.0 >> 16) as u8,
            self.0 as u16
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

#[cfg(feature = "telemetry")]
impl Peer {

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

    fn update_recv_stats(&self, bytes: u64, local: &Arc<KeyId>) {
        self.update_stats(&self.recv_state, bytes, local) 
    }

    fn update_send_stats(&self, bytes: u64, local: &Arc<KeyId>) {
        self.update_stats(&self.send_state, bytes, local) 
    }

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
    count: AtomicU64,
    ordinary: Queue<SendJob>,
    priority: Queue<SendJob>,
    lock: Mutex<()>,
    sync: Condvar
}

impl SendPipeline {

    fn new(
        #[cfg(feature = "telemetry")]
        ordinary_metric: Arc<Metric>,
        #[cfg(feature = "telemetry")]
        priority_metric: Arc<Metric>
    ) -> Self {
        Self {
            count: AtomicU64::new(0),
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
                self.count.fetch_sub(1, atomic::Ordering::Relaxed);
                return Ok(ret)
            }
            if self.count.load(atomic::Ordering::Relaxed) > 0 {
                continue
            }
            let _mux = self.sync.wait(
                self.lock.lock().map_err(|_| error!("Queue mutex poisoned"))?
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
        queue.put(job);
        self.count.fetch_add(1, atomic::Ordering::Relaxed);
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
type Peers = lockfree::map::Map<Arc<KeyId>, Peer>;
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
    channels_recv: Arc<ChannelsRecv>,
    channels_send: Arc<ChannelsSend>,
    channels_wait: Arc<ChannelsSend>,
    config: AdnlNodeConfig,
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
    allocated: AdnlAlloc
}

impl AdnlNode {

    const CLOCK_TOLERANCE_SEC: i32 = 60; 
    const MAX_ADNL_MESSAGE: usize = 1024;
    const MAX_PACKETS_IN_PROGRESS: u64 = 512;
    const SIZE_BUFFER: usize = 2048;
    const TIMEOUT_ADDRESS_SEC: i32 = 1000;       
    const TIMEOUT_CHANNEL_RESET_SEC: u64 = 30;   
    const TIMEOUT_QUERY_MIN_MS: u64 = 500;   
    const TIMEOUT_QUERY_MAX_MS: u64 = 5000; 
    const TIMEOUT_QUERY_STOP_MS: u64 = 1; 
    const TIMEOUT_SHUTDOWN_MS: u64 = 2000; 
    const TIMEOUT_TRANSFER_SEC: u64 = 3;
    
    /// Constructor
    pub async fn with_config(mut config: AdnlNodeConfig) -> Result<Arc<Self>> {
        let peers = lockfree::map::Map::new();
        let mut added = false;
        for key in config.keys.iter() {
            peers.insert(key.val().id().clone(), Arc::new(lockfree::map::Map::new()));
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
        let incinerator = lockfree::map::SharedIncin::new();
        #[cfg(feature = "telemetry")] 
        let telemetry = {
            let ordinary = TelemetryByStage::with_priority(false);
            let priority = TelemetryByStage::with_priority(true);
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
            channels_recv: Arc::new(lockfree::map::Map::new()), 
            channels_send: Arc::new(lockfree::map::Map::with_incin(incinerator.clone())),
            channels_wait: Arc::new(lockfree::map::Map::with_incin(incinerator)),
            config, 
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
            allocated
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
        let socket_recv = Socket::new(Domain::ipv4(), Type::dgram(), None)?;
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
                    let addr: SockAddr = SocketAddr::new(
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
                node_loop.stop.fetch_add(1, atomic::Ordering::Relaxed);
                log::warn!(target: TARGET, "Node loopback exited");
            }
        );
        Ok(())
    }       

    pub async fn stop(&self) {
        log::warn!(target: TARGET, "Stopping ADNL node");
        self.stop.fetch_add(1, atomic::Ordering::Relaxed);
        loop {
            tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP_MS)).await;
            if self.stop.load(atomic::Ordering::Relaxed) >= 6 {
                break
            }
        }
        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_SHUTDOWN_MS)).await;
        log::warn!(target: TARGET, "ADNL node stopped");
    }

    /// Add key
    pub fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
        let ret = self.config.add_key(key, tag)?;
        add_unbound_object_to_map(
            &self.peers,
            ret.clone(),
            || Ok(Arc::new(lockfree::map::Map::new()))
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
        peer_key: &Arc<KeyOption>
    ) -> Result<Option<Arc<KeyId>>> {
        if peer_key.id() == local_key {
            return Ok(None)
        }
        let IpAddress(peer_ip_address) = peer_ip_address;
        let mut error = None;
        let mut ret = peer_key.id().clone();
        let result = self.peers(local_key)?.insert_with(
            ret.clone(), 
            |key, inserted, found| if let Some((_, found)) = found {
                ret = key.clone();
                found.address.ip_address.store(
                    *peer_ip_address, 
                    atomic::Ordering::Relaxed
                );
                lockfree::map::Preview::Discard
            } else if inserted.is_some() {
                ret = key.clone(); 
                lockfree::map::Preview::Keep
            } else {
                let address = AdnlNodeAddress::from_ip_address_and_key(
                    IpAddress(*peer_ip_address),
                    peer_key.clone()        
                );
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
                "Added ADNL peer with keyID {}, key {} to {}", 
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
        Ok(peers.val().remove(peer_key).is_some())
    }

    /// Node IP address
    pub fn ip_address(&self) -> &IpAddress {
        self.config.ip_address()
    }

    /// Node key by ID
    pub fn key_by_id(&self, id: &Arc<KeyId>) -> Result<Arc<KeyOption>> {
        self.config.key_by_id(id)
    }

    /// Node key by tag
    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<KeyOption>> {
        self.config.key_by_tag(tag)
    }

    /// Parse other's address list
    pub fn parse_address_list(list: &AddressList) -> Result<IpAddress> { 
        if list.addrs.is_empty() {
            fail!("Empty address list")
        }
        let version = Version::get();
        if (list.version > version) || (list.reinit_date > version) {
            fail!("Address list version is too high: {} vs {}", list.version, version)
        }
        if (list.expire_at != 0) && (list.expire_at < version) {
            fail!("Address list is expired")
        }
        let ret = match &list.addrs[0] {
            Address::Adnl_Address_Udp(x) => IpAddress::from_ip_and_port(
                x.ip as u32,
                x.port as u16
            ),
            _ => fail!("Only IPv4 address format is supported")
        };
        Ok(ret)
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
 
        async fn graceful_close<T>(mut reader: tokio::sync::mpsc::UnboundedReceiver<T>) {
            reader.close();
            while let Some(_) = reader.recv().await {
            }
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
                                    graceful_close(reader).await
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
                        graceful_close(reader).await;
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
    pub fn reset_peers(&self, peers: &AdnlPeers) -> Result<()> {
        let peer_list = self.peers(peers.local())?;
        let peer = peer_list.get(peers.other()).ok_or_else(
            || error!("Try to reset unknown peer pair {} -> {}", peers.local(), peers.other())
        )?;
        log::warn!(target: TARGET, "Resetting peer pair {} -> {}", peers.local(), peers.other());
        let peer = peer.val();
        let address = AdnlNodeAddress::from_ip_address_and_key(
            IpAddress(peer.address.ip_address.load(atomic::Ordering::Relaxed)),
            peer.address.key.clone()        
        )?;
        self.channels_wait
            .remove(peers.other())
            .or_else(|| self.channels_send.remove(peers.other()))
            .and_then(
                |removed| {
                    let peer = Peer {
                        address,
                        recv_state: PeerState::for_receive_with_reinit_date(
                            peer.recv_state.reinit_date.load(atomic::Ordering::Relaxed) + 1,
                            #[cfg(feature = "telemetry")]
                            self, 
                            #[cfg(feature = "telemetry")]
                            peers
                        ),
                        send_state: PeerState::for_send(
                            #[cfg(feature = "telemetry")]
                            self, 
                            #[cfg(feature = "telemetry")]
                            peers
                        ),
                        counter: self.allocated.peers.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    self.telemetry.allocated.peers.update(
                        self.allocated.peers.load(atomic::Ordering::Relaxed)
                    );
                    peer_list.insert(peers.other().clone(), peer);
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
        match self.send_message_to_peer(msg, &peers, false)? {
            MessageRepeat::Unapplicable => Ok(()), 
            x => fail!("INTERNAL ERROR: bad repeat {:?} in ADNL custom message", x)
        }
    }

    async fn add_subchannels(&self, channel: Arc<AdnlChannel>, wait: bool) -> Result<()> {
        let peer = self.peers(&channel.local_key)?;
        let peer = peer.get(&channel.other_key).ok_or_else(
            || error!("Cannot add subchannels to unknown peer {}", channel.other_key)
        )?;
        let peer = peer.val();
        let added = if wait {
            let mut prev = None;
            let added = add_counted_object_to_map_with_update(
                &self.channels_wait,
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
                    || if let Some(removed) = self.channels_send.remove(&channel .other_key) {
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
                &self.channels_send,
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
                self.channels_wait.get(&channel.other_key)
            } else {
                self.channels_send.get(&channel.other_key)
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
        other_key: Option<Arc<KeyId>>
    ) -> Result<Option<Arc<KeyId>>> {
        let ret = if let Some(other_key) = &other_key {
            if packet.from.is_some() || packet.from_short.is_some() {
                fail!("Explicit source address inside channel packet")
            }
            other_key.clone()
        } else if let Some(pub_key) = &packet.from {
            let key = Arc::new(KeyOption::from_tl_public_key(pub_key)?);
            let other_key = key.id().clone();
            if let Some(id) = &packet.from_short {
                if other_key.data() != &id.id.0 {
                    fail!("Mismatch between ID and key inside packet")
                }
            }
            if let Some(address) = &packet.address {
                let ip_address = Self::parse_address_list(address)?;
                self.add_peer(&local_key, &ip_address, &key)?;
            }
            other_key
        } else if let Some(id) = &packet.from_short {
            KeyId::from_data(id.id.0)
        } else {
            fail!("No other key data inside packet: {:?}", packet)
        };
        let dst_reinit_date = &packet.dst_reinit_date;
        let reinit_date = &packet.reinit_date;
        if dst_reinit_date.is_some() != reinit_date.is_some() {
            fail!("Destination and source reinit dates mismatch")
        }
        let peer = self.peers(&local_key)?;
        let peer = if other_key.is_some() {
            if let Some(channel) = self.channels_send.get(&ret) {
                peer.get(&channel.val().other_key)
            } else {
                fail!("Unknown channel, ID {:x?}", ret)
            }
        } else {
            peer.get(&ret) 
        };
        let peer = if let Some(peer) = peer {
            peer
        } else {
            fail!("Unknown peer {}", ret)
        };
        let peer = peer.val();
        if let (Some(dst_reinit_date), Some(reinit_date)) = (dst_reinit_date, reinit_date) {
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
        }
        if let Some(seqno) = &packet.seqno {
            match peer.recv_state.save_seqno(*seqno as u64, priority).await {
                Err(e) => fail!("Peer {} ({:?}): {}", ret, other_key, e),
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
        let peer = if let Some(peer) = peer.get(other_key) {
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
            local_pub.replace(local_pub_key.clone());
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
            if let Some(removed) = self.channels_wait.remove(&channel.other_key) {
                let result = self.channels_send.reinsert(removed);
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
            let transfer_id = get256(&part.hash);
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
                                        log::debug!(
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
                let mut local_pub = Some(get256(&confirm.peer_key).clone());
                let channel = self.create_channel(
                    peers, 
                    &mut local_pub, 
                    get256(&confirm.key), 
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
                    get256(&create.key), 
                    "creation"
                )?;
                let msg = if let Some(local_pub) = local_pub {
                    ConfirmChannel {
                        key: ton::int256(local_pub),
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
            let repeat = self.send_message_to_peer(msg, peers, priority)?;
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
        let query_id = get256(&answer.query_id).clone();
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
        let query_id = &query.query_id;
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
                    return Ok(Some(deserialize(answer)?)),
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
        let (priority, local_key, other_key) = match subchannel {
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
                (false, channel.local_key.clone(), Some(channel.other_key.clone()))
            },
            Subchannel::Priority(channel) => {
                self.decrypt_packet_from_channel(&mut packet.buf, &channel, true)?;
                (true, channel.local_key.clone(), Some(channel.other_key.clone()))
            }
        };
        let pkt = deserialize(&packet.buf[..])?
            .downcast::<AdnlPacketContentsBoxed>()
            .map_err(|pkt| failure::format_err!("Unsupported ADNL packet format {:?}", pkt))?
            .only();
        let other_key = if let Some(key) = self.check_packet(
            &pkt, 
            priority, 
            &local_key, 
            other_key
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
        let peers = Arc::new(AdnlPeers::with_keys(local_key, other_key));
        #[cfg(feature = "telemetry")]
        if let Some(peer) = self.peers(peers.local())?.get(peers.other()) {
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
            let channel = self.channels_send.get(peers.other()).map(|guard| guard.val().clone());
            (channel, self.send_message_to_peer(msg, &peers, priority)?)
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
    ) -> Result<MessageRepeat> {

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
                hash: ton::int256(hash.clone()),
                total_size: data.len() as i32,
                offset: *offset as i32,
                data: ton::bytes(part)
            }.into_boxed();
            *offset = next;
            ret
        }

        log::trace!(target: TARGET, "Send message {:?}", msg.object);

        let peer = self.peers(peers.local())?;
        let peer = if let Some(peer) = peer.get(peers.other()) {
            peer
        } else {
            fail!("Unknown peer {}", peers.other())
        };
        let peer = peer.val();
        let src = self.key_by_id(peers.local())?;
        let dst = peers.other();
        let channel = self.channels_send.get(dst);
        let create_channel_msg = if channel.is_none() && self.channels_wait.get(dst).is_none() {
            log::debug!(target: TARGET, "Create channel {} -> {}", src.id(), dst);
            Some(
                CreateChannel {
                    key: ton::int256(peer.address.channel_key.pub_key()?.clone()),
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
        let channel = if let Some(ref channel) = channel {
            Some(channel.val())
        } else {
            None
        };

        if size <= Self::MAX_ADNL_MESSAGE {
            if let Some(create_channel_msg) = create_channel_msg {
                log::trace!(target: TARGET, "Send with message {:?}", create_channel_msg);
                self.send_packet(
                    peer, 
                    &src, 
                    channel, 
                    None, 
                    Some(vec![create_channel_msg, msg.object]),
                    priority,
                    #[cfg(feature = "telemetry")]
                    msg.tag
                )
            } else {
                self.send_packet(
                    peer, 
                    &src, 
                    channel, 
                    Some(msg.object), 
                    None, 
                    priority,
                    #[cfg(feature = "telemetry")]
                    msg.tag
                )
            }
        } else {
            let data = serialize(&msg.object)?;
            let hash = sha2::Sha256::digest(&data);
            let hash = arrayref::array_ref!(hash.as_slice(), 0, 32);            
            let mut offset = 0;
            let mut repeat = if let Some(create_channel_msg) = create_channel_msg {
                let part_msg = build_part_message(
                    &data[..], 
                    hash, 
                    &mut offset, 
                    Self::MAX_ADNL_MESSAGE - SIZE_CREATE_CHANNEL_MSG
                );
                self.send_packet(
                    peer, 
                    &src, 
                    channel, 
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
                    hash, 
                    &mut offset, 
                    Self::MAX_ADNL_MESSAGE
                );
                let upd = self.send_packet(
                    peer, 
                    &src, 
                    channel, 
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
            Ok(repeat)
        }

    }

    fn send_packet(
        &self, 
        peer: &Peer,
        source: &KeyOption,
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
                    if peer.send_state.seqno(true) > 10 {
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
        let mut data = serialize(
            &AdnlPacketContents {
                rand1: ton::bytes(Self::gen_rand()),
                from: if channel.is_some() {
                    None
                } else {
                    Some(source.into_tl_public_key()?)
                },
                from_short: if channel.is_some() {
                    None
                } else {
                    Some(
                        AdnlIdShort {
                            id: ton::int256(source.id().data().clone())
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
            }.into_boxed()
        )?;
        if let Some(channel) = channel {
            if priority {
                channel.encrypt_priority(&mut data)?;
            } else {
                channel.encrypt_ordinary(&mut data)?;
            }
        } else {
            let (_, key) = KeyOption::with_type_id(source.type_id())?;
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
            let hash = sha2::Sha256::digest(&buf);
            if arrayref::array_ref!(hash.as_slice(), 0, 32) != transfer_id {
                fail!("Bad hash of ADNL transfer {}", base64::encode(transfer_id))
            }
            let msg = deserialize(&buf)?
                .downcast::<AdnlMessage>()
                .map_err(|msg| error!("Unsupported ADNL messge {:?}", msg))?;
            Ok(Some(msg))
        } else {
            log::debug!("Received ADNL part {} (total {})", received, transfer.total);
            Ok(None)
        }
    }

}
