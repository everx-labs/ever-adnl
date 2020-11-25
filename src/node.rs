use crate::{
    from_slice, 
    common::{
        add_object_to_map, add_object_to_map_with_update, AdnlCryptoUtils, AdnlHandshake, 
        AdnlPeers, AdnlPingSubscriber, deserialize, get256, hash, KeyId, KeyOption, 
        KeyOptionJson, Query, QueryCache, QueryId, serialize, Subscriber, TARGET, UpdatedAt, 
        Version
    }
};
use aes_ctr::stream_cipher::SyncStreamCipher;
use rand::Rng;
use sha2::Digest;
use std::{
    cmp::{min, Ordering}, fmt::{self, Debug, Display, Formatter}, 
    net::{IpAddr, Ipv4Addr, SocketAddr}, ops::Deref, 
    sync::{Arc, atomic::{self, AtomicI32, AtomicU32, AtomicU64, AtomicUsize}},
    time::Duration
};
use ton_api::{
    IntoBoxed, 
    ton::{
        self, TLObject,  
        adnl::{
            Address, Message as AdnlMessage, PacketContents as AdnlPacketContents, 
            address::address::Udp, addresslist::AddressList, id::short::Short as AdnlIdShort,  
            message::message::{
                Answer as AdnlAnswerMessage, ConfirmChannel, CreateChannel, 
                Custom as AdnlCustomMessage, Part as AdnlPartMessage, Query as AdnlQueryMessage
            }, 
            packetcontents::PacketContents
        },
        pub_::publickey::Aes as AesKey
    }
};
use ton_types::{error, fail, Result};

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
        let ret = add_object_to_map(
            &self.cache,
            address.clone(),
            || {
                let upper = self.upper.fetch_add(1, atomic::Ordering::Relaxed);
                index = upper;
                if index >= self.limit {
                    index %= self.limit;
                    self.upper.compare_and_swap(
                        upper + 1, 
                        index, 
                        atomic::Ordering::Relaxed
                    );
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

    pub fn random(&self, skip: Option<&lockfree::set::Set<Arc<KeyId>>>) -> Option<Arc<KeyId>> {
        let max = self.count();
        for _ in 0..10 {
            if let Some(ret) = self.index.get(&rand::thread_rng().gen_range(0, max)) {
                if let Some(skip) = skip {
                    if skip.contains(ret.val()) {
                        continue
                    }
                }
                return Some(ret.val().clone())
            }
        } 
        None
    }

    pub fn random_set(
        &self, 
        dst: &AddressCache, 
        skip: Option<&lockfree::set::Set<Arc<KeyId>>>,
        mut n: u32
    ) -> Result<()> {
        n = min(self.count(), n);
        while n > 0 {
            if let Some(key_id) = self.random(skip) {
                dst.put(key_id)?;
                n -= 1;
            } else {
                break;
            }
        }
/*
        if dst.count() >= self.count() {
            return Ok(())
        }
        n = min(self.count() - dst.count(), n);
        while n > 0 {
            if let Some(key_id) = self.random() {
                if dst.put(key_id)? {
                    n -= 1
                }
            } else {
                break;
            }
        }
*/
        Ok(())
    }
  
    fn find_by_index(&self, index: u32) -> Option<Arc<KeyId>> {
        if let Some(address) = self.index.get(&index) {
            Some(address.val().clone())
        } else {
            None
        }
    }

}

/// ADNL channel
struct AdnlChannel {
    local_key: Arc<KeyId>,
    other_key: Arc<KeyId>,
    drop: AtomicU32,
    recv: ChannelSide,
    send: ChannelSide
}

struct ChannelSide {
    id: ChannelId,
    secret: [u8; 32]
}

impl AdnlChannel {
    
    fn with_keys(
        local_key: &Arc<KeyId>, 
        channel_pvt_key: &Arc<KeyOption>, 
        other_key: &Arc<KeyId>,
        channel_pub_key: &[u8; 32]
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
        Ok(
            Self { 
                local_key: local_key.clone(), 
                other_key: other_key.clone(), 
                drop: AtomicU32::new(0),
                recv: Self::build_side(fwd_secret)?,
                send: Self::build_side(rev_secret)?
            }
        )
    }

    fn build_side(secret: [u8; 32]) -> Result<ChannelSide> {
        let ret = ChannelSide{
            id: Self::calc_id(&secret)?, 
            secret 
        };
        Ok(ret)
    }

    fn calc_id(secret: &[u8; 32]) -> Result<ChannelId> {
        let object = AesKey {
            key: ton::int256(secret.clone())
        };
        hash(object)
    }

    fn decrypt(&self, buf: &mut Vec<u8>) -> Result<()> {
        if buf.len() < 64 {
            fail!("Channel message is too short: {}", buf.len())
        }
        Self::process_data(buf, &self.recv.secret);
        if !sha2::Sha256::digest(&buf[64..]).as_slice().eq(&buf[32..64]) {
            fail!("Bad channel message checksum");
        }
        buf.drain(0..64);
        Ok(())
    }

    fn encrypt(&self, buf: &mut Vec<u8>) -> Result<()> {
        let checksum = {
            let checksum = sha2::Sha256::digest(&buf[..]);
            let checksum = checksum.as_slice();
            from_slice!(checksum, 32)
        };
        let len = buf.len();
        buf.resize(len + 64, 0);
        buf[..].copy_within(..len, 64);                                                         
        buf[..32].copy_from_slice(self.send_id());
        buf[32..64].copy_from_slice(&checksum[..]);
        Self::process_data(buf, &self.send.secret);
        Ok(())
    }

    fn recv_id(&self) -> &ChannelId {
        &self.recv.id
    }

    fn send_id(&self) -> &ChannelId {
        &self.send.id
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
    tags: lockfree::map::Map<usize, Arc<KeyId>>,
    keys: lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>
}

#[derive(serde::Deserialize, serde::Serialize)]
struct AdnlNodeKeyJson {
    tag: usize,
    data: KeyOptionJson
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AdnlNodeConfigJson {
    ip_address: String,
    keys: Vec<AdnlNodeKeyJson>
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
            tags: lockfree::map::Map::new(),
            keys: lockfree::map::Map::new()
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
        keys: Vec<([u8; 32], usize)>
    ) -> Result<(AdnlNodeConfigJson, Self)> {
        let mut json_keys = Vec::new();
        let mut tags_keys = Vec::new();
        for (key, tag) in keys {
            let (json, key) = KeyOption::from_type_and_private_key(type_id, &key)?;
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
            keys: json_keys
        };
        Ok((json, Self::from_ip_address_and_keys(ip_address, tags_keys)?))
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
            tags: lockfree::map::Map::new(),
            keys: lockfree::map::Map::new()
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
        let mut jsons = Vec::new();
        let mut keys = Vec::new();
        for tag in tags {
            let (json, key) = KeyOption::with_type_id(type_id)?;
            jsons.push(
                AdnlNodeKeyJson {
                    tag,
                    data: json
                }
            );
            keys.push((key, tag));            
        }
        let ret = Self::from_ip_address_and_keys(ip_address, keys)?;
        let json = AdnlNodeConfigJson { 
            ip_address: ip_address.to_string(),
            keys: jsons
        };
        Ok((json, ret))
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

    fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
        let mut ret = key.id().clone();
        let added = add_object_to_map_with_update(
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
            add_object_to_map_with_update(
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

    fn delete_key(&self, key: &Arc<KeyId>, tag: usize) -> Result<bool> {
        let removed_key = self.keys.remove(key);
        if let Some(removed) = self.tags.remove(&tag) {
            if removed.val() != key {
                fail!("Expected {} key with tag {} but got {}", key, tag, removed.val())
            }
        }
        Ok(removed_key.is_some())
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

#[derive(Debug)]
enum Job {
    Send(SendJob),
    Stop
}

struct Peer {
    address: AdnlNodeAddress,
    recv_state: PeerState,
    send_state: PeerState
}

struct PeerState {
    index: AtomicU64,
    masks: [AtomicU64; 8],
    reinit_date: AtomicI32,
    seqno: AtomicU64,
    window: Option<AtomicU64>
}

impl PeerState {

    const INDEX_MASK: u8 = 0xFF;
    const IN_TRANSIT: u64 = 0xFFFFFFFFFFFFFFFF;
/*    
    const WINDOW: i8 = 32;
    const MARKER: i8 = 64 - Self::WINDOW;
*/

    fn for_receive_with_reinit_date(reinit_date: i32) -> Self {
        Self {
            index: AtomicU64::new(0),
            masks: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)
            ],
            reinit_date: AtomicI32::new(reinit_date),
            seqno: AtomicU64::new(0),
            window: Some(AtomicU64::new(0))
        }
    }

    fn for_send() -> Self {
        Self {
            index: AtomicU64::new(0),
            masks: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)
            ],
            window: None,
            reinit_date: AtomicI32::new(0),
            seqno: AtomicU64::new(0)
        }
    }

    fn load_seqno(&self) -> u64 {
        self.seqno.fetch_add(1, atomic::Ordering::Relaxed) + 1
    }
    fn reinit_date(&self) -> i32 {
        self.reinit_date.load(atomic::Ordering::Relaxed)
    }
    fn reset_reinit_date(&self, reinit_date: i32) {
        self.reinit_date.store(reinit_date, atomic::Ordering::Relaxed)
    }
    fn seqno(&self) -> u64 {
        self.seqno.load(atomic::Ordering::Relaxed)
    }

    async fn reset_seqno(&self, seqno: u64) -> Result<()> {
        loop {
            let index = self.index.load(atomic::Ordering::Relaxed);
            if index == Self::IN_TRANSIT {
                tokio::task::yield_now().await;
                continue
            }
            if self.index.compare_and_swap(
                index, 
                Self::IN_TRANSIT, 
                atomic::Ordering::Relaxed
            ) != index {
                continue
            }
            break
        }
        for i in 0..8 {
            self.masks[i].store(
                if i == 4 {
                    1
                } else {
                    0
                }, 
                atomic::Ordering::Relaxed
            )
        }
        self.seqno.store(seqno, atomic::Ordering::Relaxed);
        if let Some(window) = &self.window {
            window.store(seqno as u32 as u64, atomic::Ordering::Relaxed)
        }
        if self.index.compare_and_swap(
            Self::IN_TRANSIT, 
            seqno & !(Self::INDEX_MASK as u64),
            atomic::Ordering::Relaxed
        ) != Self::IN_TRANSIT {
            fail!("INTERNAL ERROR: ADNL packet seqno reset mismatch ({:x})", seqno)
        }
        Ok(())
    }

    async fn save_seqno(&self, seqno: u64) -> Result<()> {
        let seqno_masked = seqno & Self::INDEX_MASK as u64;
        let seqno_normalized = seqno & !(Self::INDEX_MASK as u64); 
        loop {
            let index = self.index.load(atomic::Ordering::Relaxed);
            if index == Self::IN_TRANSIT {
                tokio::task::yield_now().await;
                continue
            }
            let index_masked = index & Self::INDEX_MASK as u64;
            let index_normalized = index & !(Self::INDEX_MASK as u64);
            if index_normalized > seqno_normalized + Self::INDEX_MASK as u64 + 1 {
                // Out of the window
                fail!(
                    "ADNL packet with seqno {:x} is too old ({:x})", 
                    seqno, 
                    index_normalized
                )
            }
            // Masks format: 
            // lower0, lower1, lower2, lower3, upper0, upper1, upper2, upper3
            let mask = 1 << seqno_masked % 64;
            let mask_offset = if index_normalized > seqno_normalized {
                // Lower part of the window
                Some(0)
            } else if index_normalized == seqno_normalized {
                // Upper part of the window
                Some(4)
            } else {
                None
            };
            let next_index = if let Some(mask_offset) = mask_offset {
                let mask_offset = mask_offset + seqno_masked as usize / 64;
                let already_received = 
                    self.masks[mask_offset].load(atomic::Ordering::Relaxed) & mask;
                if self.index.load(atomic::Ordering::Relaxed) != index {
log::warn!(target: TARGET, "ADNL4");
                    continue
                }
                if already_received != 0 {
                    // Already received
                    fail!("ADNL packet with seqno {:x} was already received", seqno)
                }
                if self.index.compare_and_swap(
                    index, 
                    Self::IN_TRANSIT, 
                    atomic::Ordering::Relaxed
                ) != index {
log::warn!(target: TARGET, "ADNL5");
                    continue
                }
                self.masks[mask_offset].fetch_or(mask, atomic::Ordering::Relaxed);
                index
            } else {
                if self.index.compare_and_swap(
                    index, 
                    Self::IN_TRANSIT, 
                    atomic::Ordering::Relaxed
                ) != index {
log::warn!(target: TARGET, "ADNL6");
                    continue
                }
                if index_normalized + 1 == seqno_normalized {
                    for i in 0..4 {
                        self.masks[i].store(
                            self.masks[i + 4].load(atomic::Ordering::Relaxed),
                            atomic::Ordering::Relaxed
                        )
                    }
                    for i in 4..8 {
                        self.masks[i].store(0, atomic::Ordering::Relaxed)
                    }
                } else {
                    for i in 0..8 {
                        self.masks[i].store(0, atomic::Ordering::Relaxed)
                    }
                }
                seqno_normalized
            };
            let last_seqno = self.seqno.load(atomic::Ordering::Relaxed);
            if last_seqno < seqno {
                self.seqno.store(seqno, atomic::Ordering::Relaxed)
            }
            let index_masked = (index_masked + 1) & !(Self::INDEX_MASK as u64);
            if self.index.compare_and_swap(
                Self::IN_TRANSIT, 
                next_index | index_masked,
                atomic::Ordering::Relaxed
            ) != Self::IN_TRANSIT {
                fail!("INTERNAL ERROR: ADNL packet seqno sync mismatch ({:x})", seqno)
            }
            break
        }
        Ok(())
    }

/*
    fn save_seqno_old(&self, seqno: u64) -> Result<()> {
        let window = self.window.as_ref().ok_or_else(
            || error!("INTERNAL ERROR: unexpected save_seqno() call")
        )?;
        loop {
            let old_seqno = self.seqno.load(atomic::Ordering::Relaxed);
            match Self::evaluate(old_seqno, seqno, false)? {
                // Older packet
                x if x < 0 => {
                    let mask = window.load(atomic::Ordering::Relaxed);
                    if mask as u32 != old_seqno as u32 {
                        // Re-read state
                        continue
                    } 
                    let bit = 1u64 << (-x + Self::MARKER);
                    if mask & bit != 0 {
                        // Already received
                        fail!("ADNL packet with seqno {} already received {:x}", seqno, mask)  
                    }
                    if !Self::try_set(window, mask, mask | bit) {
                        // Re-read state
                        continue
                    }
                },
                // Newer packet
                _ => {
                    if !Self::try_set(&self.seqno, old_seqno, seqno) {
                        // Re-read state
                        continue
                    }
                    loop {
                        let mask = window.load(atomic::Ordering::Relaxed);
                        let new_mask = match Self::evaluate(mask, seqno, true)? {
                            x if x < 0 => mask | (1u64 << (-x + Self::MARKER)),
                            x => (seqno as u32) as u64 | (1u64 << Self::MARKER) | 
                            if x >= Self::WINDOW {
                                0
                            } else {
                                (mask & 0xFFFFFFFF00000000u64) << x
                            } 
                        };
                        if Self::try_set(window, mask, new_mask) {
                            break
                        }
                    } 
                }
            }
            break
        }
        Ok(())
    }

    fn evaluate(old: u64, new: u64, as_window: bool) -> Result<i8> {
        let diff = if as_window {
            (new as u32 as i64 - old as u32 as i64) as i32
        } else {
            let diff = new as i64 - old as i64;
            if diff >= (1i64 << Self::MARKER) {
                fail!("ADNL packet with seqno {} is too new ({})", new, old)
            }
            diff as i32
        };
        match diff {
            // Already received
            0 => fail!("ADNL packet with seqno {} just received", new),
            // Too late
            x if x <= -Self::WINDOW as i32 => 
                fail!("ADNL packet with seqno {} is too old ({})", new, old),
            // Not too late
            x if x < 0 => Ok(x as i8),
            // Just update
            x => Ok(min(x, Self::WINDOW as i32) as i8)
        }
    }

    fn try_set(atomic: &AtomicU64, old: u64, new: u64) -> bool {
        atomic
            .compare_exchange(old, new, atomic::Ordering::Relaxed, atomic::Ordering::Relaxed)
            .is_ok()
    }
*/

}

#[derive(Debug)]
struct SendJob {
    destination: u64,
    data: Vec<u8>
}

struct Transfer {
    data: lockfree::map::Map<usize, Vec<u8>>,
    received: AtomicUsize,
    total: usize,
    updated: UpdatedAt
}

type ChannelId = [u8; 32];
type ChannelsRecv = lockfree::map::Map<ChannelId, Arc<AdnlChannel>>; 
type ChannelsSend = lockfree::map::Map<Arc<KeyId>, Arc<AdnlChannel>>;
type Peers = lockfree::map::Map<Arc<KeyId>, Peer>;
type TransferId = [u8; 32];

/// ADNL node
pub struct AdnlNode {
    #[cfg(feature = "trace")]
    answers: lockfree::map::Map<QueryId, Vec<u8>>,
    config: AdnlNodeConfig,
    channels_recv: Arc<ChannelsRecv>,
    channels_send: Arc<ChannelsSend>,
    channels_wait: Arc<ChannelsSend>,
    peers: lockfree::map::Map<Arc<KeyId>, Arc<Peers>>,
    queries: Arc<QueryCache>, 
    queue_sender: tokio::sync::mpsc::UnboundedSender<Job>,
    queue_reader: lockfree::queue::Queue<tokio::sync::mpsc::UnboundedReceiver<Job>>,
    queue_local_sender: tokio::sync::mpsc::UnboundedSender<(AdnlMessage, Arc<KeyId>)>,
    queue_local_reader: lockfree::queue::Queue<
        tokio::sync::mpsc::UnboundedReceiver<(AdnlMessage, Arc<KeyId>)>
    >,
    start_time: i32,
    stop: AtomicU32,
    transfers: Arc<lockfree::map::Map<TransferId, Arc<Transfer>>>
}

impl AdnlNode {

    const CLOCK_TOLERANCE: i32 = 60;     // Seconds
    const MAX_ADNL_MESSAGE: usize = 1024;
    const SIZE_BUFFER: usize = 2048;
    const TIMEOUT_ADDRESS: i32 = 1000;       // Seconds
    const TIMEOUT_CHANNEL_RESET: u32 = 5000; // Milliseconds
    const TIMEOUT_QUERY_MIN: u64 = 500;      // Milliseconds
    const TIMEOUT_QUERY_MAX: u64 = 5000;     // Milliseconds
    const TIMEOUT_QUERY_STOP: u64 = 1;       // Milliseconds
    const TIMEOUT_SHUTDOWN: u64 = 2000;      // Milliseconds
    const TIMEOUT_TRANSFER: u64 = 3;         // Seconds

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
        let (queue_sender, queue_reader) = tokio::sync::mpsc::unbounded_channel();
        let (queue_local_sender, queue_local_reader) = tokio::sync::mpsc::unbounded_channel();
        let incinerator = lockfree::map::SharedIncin::new();
        let ret = Self {
            #[cfg(feature = "trace")]
            answers: lockfree::map::Map::new(),
            config, 
            channels_recv: Arc::new(lockfree::map::Map::new()), 
            channels_send: Arc::new(lockfree::map::Map::with_incin(incinerator.clone())), 
            channels_wait: Arc::new(lockfree::map::Map::with_incin(incinerator)), 
            peers,
            queries: Arc::new(lockfree::map::Map::new()), 
            queue_sender,
            queue_reader: lockfree::queue::Queue::new(),
            queue_local_sender,
            queue_local_reader: lockfree::queue::Queue::new(),
            start_time: Version::get(),
            stop: AtomicU32::new(0),
            transfers: Arc::new(lockfree::map::Map::new())
        };
        ret.queue_reader.push(queue_reader);
        ret.queue_local_reader.push(queue_local_reader);
        Ok(Arc::new(ret))
    }

    /// Start node 
    pub async fn start(
        node: &Arc<Self>, 
        mut subscribers: Vec<Arc<dyn Subscriber>>
    ) -> Result<()> {
        let mut queue_reader = node.queue_reader.pop().ok_or_else(
            || error!("ADNL node already started")
        )?;
        let mut queue_local_reader = node.queue_local_reader.pop().ok_or_else(
            || error!("ADNL node already started")
        )?;
        let (mut receiver, mut sender) = 
            tokio::net::UdpSocket::bind(
                &SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED), 
                    node.config.ip_address.port()
                )
            )
            .await?
            .split();
        let node_stop = node.clone();
        // Stopping watchdog
        tokio::spawn(
            async move {
                loop {
                    tokio::time::delay_for(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
                    if node_stop.stop.load(atomic::Ordering::Relaxed) > 0 {      
                        if let Err(e) = node_stop.queue_sender.send(Job::Stop) {
                            log::warn!(target: TARGET, "Cannot close node socket: {}", e);
                        }
                        let stop = (AdnlMessage::Adnl_Message_Nop, KeyId::from_data([0u8; 32]));
                        if let Err(e) = node_stop.queue_local_sender.send(stop) {
                            log::warn!(target: TARGET, "Cannot close node loopback: {}", e);
                        }
                        break
                    }
                }
                node_stop.stop.fetch_add(1, atomic::Ordering::Relaxed);
                log::warn!(target: TARGET, "Node stopping watchdog exited");
            }
        );
        subscribers.push(Arc::new(AdnlPingSubscriber));
        let subscribers = Arc::new(subscribers);
        let subscribers_local = subscribers.clone();
        // Remote connections
        let node_recv = node.clone();
        tokio::spawn(
            async move {
                let mut buf_source = None;
                loop {            
                    let buf = buf_source.get_or_insert_with(
                        || {
                            let mut buf = Vec::with_capacity(Self::SIZE_BUFFER);
                            buf.resize(Self::SIZE_BUFFER, 0);
                            buf                                                       
                        }
                    );
                    let res = receiver.recv_from(&mut buf[..]).await;
                    if node_recv.stop.load(atomic::Ordering::Relaxed) > 0 {
                        break
                    }
                    let len = match res {
                        Err(e) => {
                            log::warn!(target: TARGET, "ERROR <-- {}", e);
                            continue
                        },
                        Ok((len, _)) => len
                    };
                    let mut buf = if let Some(buf) = buf_source.take() {
                        buf
                    } else {
                        continue
                    };
                    buf.truncate(len);
                    let node_recv = node_recv.clone();
                    let subscribers = subscribers.clone();
                    tokio::spawn (
                        async move {
                            if let Err(e) = node_recv.receive(&mut buf, &subscribers).await {
                                log::warn!(target: TARGET, "ERROR <-- {}", e)
                            }
                        }
                    );
                }
                node_recv.stop.fetch_add(1, atomic::Ordering::Relaxed);
                log::warn!(target: TARGET, "Node socket receiver exited");
            }
        );
        let node_send = node.clone();
        tokio::spawn(
            async move {
                while let Some(job) = queue_reader.recv().await {
                    let (job, stop) = match job {
                        Job::Send(job) => (job, false),
                        Job::Stop => (
                            // Send closing packet to 127.0.0.1:port
                            SendJob { 
                                destination: 
                                    0x7F0000010000u64 | node_send.config.ip_address.port() as u64,
                                data: Vec::new()
                            },
                            true
                        )
                    };
                    if let Err(e) = Self::send(&mut sender, job).await {
                        log::warn!(target: TARGET, "ERROR --> {}", e);
                    }
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
                while let Some((msg, src)) = queue_local_reader.recv().await {
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
                                Ok(Some(AdnlMessage::Adnl_Message_Answer(answer))) => answer,
                                Ok(Some(x)) => {
                                    log::warn!(target: TARGET, "Unexpected reply {:?}", x);
                                    return
                                },
                                Err(e) => {
                                    log::warn!(target: TARGET, "ERROR --> {}", e);
                                    return
                                },
                                _ => return
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
            tokio::time::delay_for(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
            if self.stop.load(atomic::Ordering::Relaxed) >= 5 {
                break
            }
        }
        tokio::time::delay_for(Duration::from_millis(Self::TIMEOUT_SHUTDOWN)).await;
        log::warn!(target: TARGET, "ADNL node stopped");
    }

    /// Add key
    pub fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
        self.config.add_key(key, tag)
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
                found.address.ip_address.store(*peer_ip_address, atomic::Ordering::Relaxed);
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
                    Ok(address) => lockfree::map::Preview::New(
                        Peer {
                            address,
                            recv_state: PeerState::for_receive_with_reinit_date(self.start_time),
                            send_state: PeerState::for_send()
                        }
                    ),
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
        let timeout = roundtrip.unwrap_or(Self::TIMEOUT_QUERY_MAX);
        if timeout < Self::TIMEOUT_QUERY_MIN {
            Self::TIMEOUT_QUERY_MIN
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
        &self, 
        query: &TLObject,
        peers: &AdnlPeers,
        timeout: Option<u64>
    ) -> Result<Option<TLObject>> {
        self.query_with_prefix(None, query, peers, timeout).await
    }

    /// Send query with prefix
    pub async fn query_with_prefix(
        &self, 
        prefix: Option<&[u8]>,
        query: &TLObject,
        peers: &AdnlPeers,
        timeout: Option<u64>
    ) -> Result<Option<TLObject>> {
        let (query_id, msg) = Query::build(prefix, query)?;
        let (ping, query) = Query::new();
        self.queries.insert(query_id, query);
log::warn!("Sent query {:02x}{:02x}{:02x}{:02x}", query_id[0], query_id[1], query_id[2], query_id[3]);
        let channel = if peers.local() == peers.other() {       
            self.queue_local_sender.send((msg, peers.local().clone()))?;
            None
        } else {
            let channel = self.channels_send.get(peers.other());
            self.send_message(msg, peers)?;
            channel
        };
        let queries = self.queries.clone();
        tokio::spawn(
            async move {
                let timeout = timeout.unwrap_or(Self::TIMEOUT_QUERY_MAX);
                tokio::time::delay_for(Duration::from_millis(timeout)).await;
                if let Err(e) = Self::update_query(&queries, query_id, None).await {
                    log::warn!(target: TARGET, "ERROR: {}", e)
                }
            }
        );
        ping.wait().await;                     
        if let Some(removed) = self.queries.remove(&query_id) {
            match removed.val() {
                Query::Received(answer) => 
                    return Ok(Some(deserialize(answer)?)),
                Query::Timeout => {
log::warn!("Dropped query {:02x}{:02x}{:02x}{:02x}", query_id[0], query_id[1], query_id[2], query_id[3]);
                    /* Monitor channel health */
                    if let Some(channel) = channel {
                        let now = Version::get() as u32;
                        let was = channel.val().drop.compare_and_swap(
                            0,
                            now + Self::TIMEOUT_CHANNEL_RESET,
                            atomic::Ordering::Relaxed
                        );
                        if (was > 0) && (was < now) {
                            self.reset_peers(peers)? 
                        }
                    }
                    return Ok(None)
                },
                _ => ()
            }
        } 
        fail!("INTERNAL ERROR: ADNL query mismatch")
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
                    peer_list.insert(
                        peers.other().clone(),
                        Peer {
                            address,
                            recv_state: PeerState::for_receive_with_reinit_date(
                                peer.recv_state.reinit_date.load(atomic::Ordering::Relaxed) + 1
                            ),
                            send_state: PeerState::for_send()
                        }
                    );
                    self.channels_recv.remove(removed.val().recv_id())
                }
             );
        Ok(())
    }

    /// Send custom message
    pub async fn send_custom(
        &self, 
        data: &[u8],
        peers: &AdnlPeers
    ) -> Result<()> {
        let msg = AdnlCustomMessage {
            data: ton::bytes(data.to_vec())
        }.into_boxed();
        self.send_message(msg, peers)
    }

    async fn check_packet(
        &self,
        packet: &AdnlPacketContents, 
        local_key: &Arc<KeyId>,
        other_key: Option<Arc<KeyId>>
    ) -> Result<Arc<KeyId>> {
        let ret = if let Some(other_key) = &other_key {
            if packet.from().is_some() || packet.from_short().is_some() {
                fail!("Explicit source address inside channel packet")
            }
            other_key.clone()
        } else if let Some(pub_key) = packet.from() {
            let key = Arc::new(KeyOption::from_tl_public_key(pub_key)?);
            let other_key = key.id().clone();
            if let Some(id) = packet.from_short() {
                if other_key.data() != &id.id.0 {
                    fail!("Mismatch between ID and key inside packet")
                }
            }
            if let Some(address) = packet.address() {
                let ip_address = Self::parse_address_list(address)?;
                self.add_peer(&local_key, &ip_address, &key)?;
            }
            other_key
        } else if let Some(id) = packet.from_short() {
            KeyId::from_data(id.id.0)
        } else {
            fail!("No other key data inside packet: {:?}", packet)
        };
        let dst_reinit_date = packet.dst_reinit_date();
        let reinit_date = packet.reinit_date();
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
                    Ordering::Less => 
                        fail!(
                            "Destination reinit date is too old: {} vs {}, {:?}", 
                            dst_reinit_date, 
                            peer.recv_state.reinit_date(),  
                            packet
                        )
                }
            }
            let other_reinit_date = peer.send_state.reinit_date();
            match reinit_date.cmp(&other_reinit_date) {
                Ordering::Equal => (),
                Ordering::Greater => if *reinit_date > Version::get() + Self::CLOCK_TOLERANCE {
                    fail!("Source reinit date is too new: {}", reinit_date)
                } else {
                    peer.send_state.reset_reinit_date(*reinit_date);
                    if other_reinit_date != 0 {
                        peer.send_state.reset_seqno(0).await?;
                        peer.recv_state.reset_seqno(0).await?;
                    }
                },
                Ordering::Less => 
                    fail!("Source reinit date is too old: {}", reinit_date)
            }
        }
        if let Some(seqno) = packet.seqno() {
            if let Err(e) = peer.recv_state.save_seqno(*seqno as u64).await {
                fail!("Peer {} ({:?}): {}", ret, other_key, e)
            }
        }
        if let Some(seqno) = packet.confirm_seqno() {
            let local_seqno = peer.send_state.seqno();
            if *seqno as u64 > local_seqno {
                fail!(
                    "Peer {}: too new ADNL packet seqno confirmed: {}, expected <= {}", 
                    ret,
                    seqno, 
                    local_seqno
                )
            }
        }
        Ok(ret)	
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
        let channel = AdnlChannel::with_keys(local_key, local_pvt_key, other_key, other_pub)?;
        log::debug!(target: TARGET, "Channel {}: {} -> {}", context, local_key, other_key);
        log::trace!(
            target: TARGET,
            "Channel send ID {}, recv ID {}", 
            base64::encode(channel.send_id()),
            base64::encode(channel.recv_id())
        );
        Ok(Arc::new(channel))
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

    async fn process(
        &self,
        subscribers: &Vec<Arc<dyn Subscriber>>,
        msg: &AdnlMessage,
        peers: &AdnlPeers,
        #[cfg(feature = "trace")]
        data: Vec<u8>
    ) -> Result<()> {
        let new_msg = if let AdnlMessage::Adnl_Message_Part(part) = msg {
            let transfer_id = get256(&part.hash);
            let added = add_object_to_map(
                &self.transfers,
                transfer_id.clone(),
                || {
                    let transfer = Transfer {
                        data: lockfree::map::Map::new(),
                        received: AtomicUsize::new(0),
                        total: part.total_size as usize,
                        updated: UpdatedAt::new()
                    };
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
                                tokio::time::delay_for(
                                    Duration::from_millis(Self::TIMEOUT_TRANSFER * 100)
                                ).await;
                                if transfer_wait.updated.is_expired(Self::TIMEOUT_TRANSFER) {
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
        let msg = match new_msg.as_ref().unwrap_or(msg) {
            AdnlMessage::Adnl_Message_Answer(answer) => {
                #[cfg(feature = "trace")] {    
                    let query_id = get256(&answer.query_id).clone();
                    if !add_object_to_map(
                        &self.answers, 
                        query_id.clone(), 
                        || Ok(data.clone())
                    )? {
                        fail!(
                            "INTERNAL ERROR: duplicated answer ({}) {:?} {:?} {:?}",
                            answer.answer.0.len(), 
                            query_id,
                            self.answers.get(&query_id),
                            data
                        )
                    }
                }
                self.process_answer(answer, peers.other()).await?;
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
                self.channels_send.insert(peers.other().clone(), channel.clone());
                self.channels_recv.insert(channel.recv_id().clone(), channel);
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
                self.channels_wait
                    .insert(peers.other().clone(), channel.clone())
                    .or(self.channels_send.remove(peers.other()))
                    .and_then(|removed| self.channels_recv.remove(removed.val().recv_id()));
                self.channels_recv.insert(channel.recv_id().clone(), channel);
                Some(msg)
            },
            AdnlMessage::Adnl_Message_Custom(custom) => {
                if !Query::process_custom(subscribers, custom, peers).await? {
                    fail!("No subscribers for custom message {:?}", custom)
                }
                None
            },
            AdnlMessage::Adnl_Message_Query(query) => {
                Self::process_query(subscribers, query, peers).await?
            },
            _ => fail!("Unsupported ADNL message {:?}", msg)
        };
        if let Some(msg) = msg {
            self.send_message(msg, peers)?;
        }
        Ok(())
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
    ) -> Result<Option<AdnlMessage>> {
        if let (true, answer) = Query::process_adnl(subscribers, query, peers).await? {
            Ok(answer)
        } else {
            fail!("No subscribers for query {:?}", query)
        }
    }

    async fn receive(
        &self, 
        buf: &mut Vec<u8>,
        subscribers: &Vec<Arc<dyn Subscriber>>,
    ) -> Result<()> {
        #[cfg(feature = "trace")]
        let trace_buf = buf.clone();
        let (local_key, other_key) = if let Some(local_key) = AdnlHandshake::parse_packet(
            &self.config.keys, 
            buf, 
            None
        )? {
            (local_key, None)
        } else if let Some(channel) = self.channels_recv.get(&buf[0..32]) {
            let channel = channel.val();
            channel.decrypt(buf)?;
            if let Some(removed) = self.channels_wait.remove(&channel.other_key) {
                let result = self.channels_send.reinsert(removed);
                if let lockfree::map::Insertion::Failed(_) = result {
                    fail!("Internal error when register send channel");
                }
            }
            /* Restore channel health */
            channel.drop.store(0, atomic::Ordering::Relaxed);
            (channel.local_key.clone(), Some(channel.other_key.clone()))
        } else {
            fail!("Received message to unknown key ID {}", base64::encode(&buf[0..32]))
        };
        let pkt = deserialize(&buf[..])?
            .downcast::<AdnlPacketContents>()
            .map_err(|pkt| failure::format_err!("Unsupported ADNL packet format {:?}", pkt))?;
        let other_key = self.check_packet(&pkt, &local_key, other_key).await?;        
        let peers = AdnlPeers::with_keys(local_key, other_key);
        if let Some(msg) = pkt.message() { 
            self.process(
                subscribers, 
                msg, 
                &peers, 
                #[cfg(feature = "trace")]
                trace_buf
            ).await?
        } else if let Some(msgs) = pkt.messages() {
            for msg in msgs.deref() {
                self.process(
                    subscribers, 
                    msg, 
                    &peers, 
                    #[cfg(feature = "trace")]
                    trace_buf.clone()
                ).await?;
            }
        } else {
            // Specifics of implementation. 
            // Address/seqno update is to be sent serarately from data
            // fail!("ADNL packet ({}) without a message: {:?}", buf.len(), pkt)
        }
        Ok(())
    }

    async fn send(sender: &mut tokio::net::udp::SendHalf, job: SendJob) -> Result<()> {
        let addr = SocketAddr::new(
            IpAddr::from(((job.destination >> 16) as u32).to_be_bytes()), 
            job.destination as u16
        );
        sender.send_to(&job.data[..], &addr).await?;
        Ok(())
    }

    fn send_message(&self, msg: AdnlMessage, peers: &AdnlPeers) -> Result<()> {
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
            40
        } else {
            0
        };
        size += match &msg {
            AdnlMessage::Adnl_Message_Answer(answer) => answer.answer.len() + 44,
            AdnlMessage::Adnl_Message_ConfirmChannel(_) => 72,
            AdnlMessage::Adnl_Message_Custom(custom) => custom.data.len() + 12,
            AdnlMessage::Adnl_Message_Query(query) => query.query.len() + 44,
            _ => fail!("Unexpected message to send {:?}", msg)  
        };
        let channel = if let Some(ref channel) = channel {
            Some(channel.val())
        } else {
            None
        };
        if size <= Self::MAX_ADNL_MESSAGE {
            if let Some(create_channel_msg) = create_channel_msg {
                self.send_packet(peer, &src, channel, None, Some(vec![create_channel_msg, msg]))
            } else {
                self.send_packet(peer, &src, channel, Some(msg), None)
            }
        } else {
            if let Some(create_channel_msg) = create_channel_msg {
                self.send_packet(peer, &src, channel, Some(create_channel_msg), None)?
            }
            let data = serialize(&msg)?;
            let hash = sha2::Sha256::digest(&data);
            let mut offset = 0;
            while offset < data.len() {
                let next = min(data.len(), offset + Self::MAX_ADNL_MESSAGE);
                let mut part = Vec::new();
                part.extend_from_slice(&data[offset..next]);
                let part = AdnlPartMessage {
                    hash: ton::int256(arrayref::array_ref!(hash.as_slice(), 0, 32).clone()),
                    total_size: data.len() as i32,
                    offset: offset as i32,
                    data: ton::bytes(part)
                }.into_boxed();
                self.send_packet(peer, &src, channel, Some(part), None)?;
                offset = next;
            };
            Ok(())
        }
    }

    fn send_packet(
        &self, 
        peer: &Peer,
        source: &KeyOption,
        channel: Option<&Arc<AdnlChannel>>, 
        message: Option<AdnlMessage>, 
        messages: Option<Vec<AdnlMessage>>
    ) -> Result<()> {
        let mut data = serialize(
            &PacketContents {
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
                    self.build_address_list(Some(Version::get() + Self::TIMEOUT_ADDRESS))?
                ),
                priority_address: None,
                seqno: Some(peer.send_state.load_seqno() as i64),
                confirm_seqno: Some(peer.recv_state.seqno() as i64),
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
            channel.encrypt(&mut data)?
        } else {
            let (_, key) = KeyOption::with_type_id(source.type_id())?;
            AdnlHandshake::build_packet(&mut data, &key, &peer.address.key)?;
        }
        let job = SendJob { 
            destination: peer.address.ip_address.load(atomic::Ordering::Relaxed),
            data
        };
        self.queue_sender.send(Job::Send(job))?;
        Ok(())
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
        let mut received = transfer.received.compare_and_swap(
            transfer.total, 
            2 * transfer.total, 
            atomic::Ordering::Relaxed
        );
        if received > transfer.total {
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
