use crate::{
    from_slice, 
    common::{
        add_object_to_map, add_object_to_map_with_update, AdnlCryptoUtils, AdnlHandshake, 
        AdnlPeers, AdnlPingSubscriber, deserialize, get256, hash, KeyId, KeyOption, 
        KeyOptionJson, Query, QueryCache, QueryId, serialize, Subscriber, TARGET, UpdatedAt, 
        Version
    }
};
#[cfg(feature = "telemetry")]
use crate::telemetry::{Metric, MetricBuilder, TelemetryItem, TelemetryPrinter};
use aes_ctr::cipher::stream::SyncStreamCipher;
use rand::Rng;
use sha2::Digest;
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    cmp::{min, Ordering}, collections::VecDeque, fmt::{self, Debug, Display, Formatter}, 
    io::ErrorKind, net::{IpAddr, Ipv4Addr, SocketAddr}, ops::Deref, 
    sync::{Arc, atomic::{self, AtomicI32, AtomicU32, AtomicU64, AtomicUsize}, mpsc},
    time::{Duration, Instant}, thread
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
    keys: lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>,
    tags: lockfree::map::Map<usize, Arc<KeyId>>,
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
            keys: json_keys,
            throughput: None
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
            keys: lockfree::map::Map::new(),
            tags: lockfree::map::Map::new(),
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
            keys: jsons,
            throughput: None
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
const HISTORY_CELLS: usize = HISTORY_BITS / 64;

pub struct PeerHistory {
    index: AtomicU64,
    masks: [AtomicU64; HISTORY_CELLS],
    seqno: AtomicU64
}                                   

impl PeerHistory {

    const INDEX_MASK: u64 = HISTORY_BITS as u64 / 2 - 1;
    const IN_TRANSIT: u64 = 0xFFFFFFFFFFFFFFFF;

    /// Constructor 
    pub fn new() -> Self {
        Self {
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
            ],
            seqno: AtomicU64::new(0)
        }
    }

    /// Print stats
    pub fn print_stats(&self) {
        let seqno = self.seqno.load(atomic::Ordering::Relaxed);
        log::info!(
            target: TARGET, 
            "Peer history: seqno {}/{:x}, mask {:x} [ {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ]",
            seqno, seqno, 
            self.index.load(atomic::Ordering::Relaxed),
            self.masks[0].load(atomic::Ordering::Relaxed),
            self.masks[1].load(atomic::Ordering::Relaxed),
            self.masks[2].load(atomic::Ordering::Relaxed),
            self.masks[3].load(atomic::Ordering::Relaxed),
            self.masks[4].load(atomic::Ordering::Relaxed),
            self.masks[5].load(atomic::Ordering::Relaxed),
            self.masks[6].load(atomic::Ordering::Relaxed),
            self.masks[7].load(atomic::Ordering::Relaxed)
        )
    }

    /// Update with specified SEQ number
    pub async fn update(&self, seqno: u64, target: &str) -> Result<bool> {
        let seqno_masked = seqno & Self::INDEX_MASK;
        let seqno_normalized = seqno & !Self::INDEX_MASK; 
        loop {
            let index = self.index.load(atomic::Ordering::Relaxed);
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
                Some(HISTORY_CELLS / 2)
            } else {
                None
            };
            let next_index = if let Some(mask_offset) = mask_offset {
                let mask_offset = mask_offset + seqno_masked as usize / 64;
                let already_received = 
                    self.masks[mask_offset].load(atomic::Ordering::Relaxed) & mask;
                if self.index.load(atomic::Ordering::Relaxed) != index {
log::warn!(target: target, "ADNL4");
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
                if self.index.compare_exchange(
                    index, 
                    Self::IN_TRANSIT, 
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed
                ).is_err() {
log::warn!(target: target, "ADNL5");
                    continue
                }
                self.masks[mask_offset].fetch_or(mask, atomic::Ordering::Relaxed);
                index
            } else {
                if self.index.compare_exchange(
                    index, 
                    Self::IN_TRANSIT, 
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed
                ).is_err() {
log::warn!(target: target, "ADNL6");
                    continue
                }
                if index_normalized + Self::INDEX_MASK + 1 == seqno_normalized {
                    for i in 0..HISTORY_CELLS / 2 {
                        self.masks[i].store(
                            self.masks[i + HISTORY_CELLS / 2].load(atomic::Ordering::Relaxed),
                            atomic::Ordering::Relaxed
                        )
                    }
                    for i in HISTORY_CELLS / 2..HISTORY_CELLS {
                        self.masks[i].store(0, atomic::Ordering::Relaxed)
                    }
                } else {
                    for i in 0..HISTORY_CELLS {
                        self.masks[i].store(0, atomic::Ordering::Relaxed)
                    }
                }
                seqno_normalized
            };
            let last_seqno = self.seqno.load(atomic::Ordering::Relaxed);
            if last_seqno < seqno {
                self.seqno.store(seqno, atomic::Ordering::Relaxed)
            }
            let index_masked = (index_masked + 1) & !Self::INDEX_MASK;
            if self.index.compare_exchange(
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
        loop {
            let index = self.index.load(atomic::Ordering::Relaxed);
            if index == Self::IN_TRANSIT {
                tokio::task::yield_now().await;
                continue
            }
            if self.index.compare_exchange(
                index, 
                Self::IN_TRANSIT, 
                atomic::Ordering::Relaxed,
                atomic::Ordering::Relaxed
            ).is_err() {
                continue
            }
            break
        }
        for i in 0..HISTORY_CELLS {
            self.masks[i].store(
                if i == HISTORY_CELLS / 2 {
                    1
                } else {
                    0
                }, 
                atomic::Ordering::Relaxed
            )
        }
        self.seqno.store(seqno, atomic::Ordering::Relaxed);
        if self.index.compare_exchange(
            Self::IN_TRANSIT, 
            seqno & !Self::INDEX_MASK,
            atomic::Ordering::Relaxed,
            atomic::Ordering::Relaxed
        ).is_err() {
            fail!("INTERNAL ERROR: peer packet seqno reset mismatch ({:x})", seqno)
        }
        Ok(())
    }

}

struct PeerState {
    history: PeerHistory,
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
            history: PeerHistory::new(),
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
            packets: Self::add_metric(node, peers, "packets/ms", false)
        }
    }

    fn for_send(
        #[cfg(feature = "telemetry")]
        node: &AdnlNode,
        #[cfg(feature = "telemetry")]
        peers: &AdnlPeers
    ) -> Self {
        Self {
            history: PeerHistory::new(),
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
            packets: Self::add_metric(node, peers, "packets/ms", true)
        }
    }

    fn load_seqno(&self) -> u64 {
        self.history.seqno.fetch_add(1, atomic::Ordering::Relaxed) + 1
    }
    fn reinit_date(&self) -> i32 {
        self.reinit_date.load(atomic::Ordering::Relaxed)
    }
    fn reset_reinit_date(&self, reinit_date: i32) {
        self.reinit_date.store(reinit_date, atomic::Ordering::Relaxed)
    }
    async fn reset_seqno(&self, seqno: u64) -> Result<()> {
        self.history.reset(seqno).await
    }
    fn seqno(&self) -> u64 {
        self.history.seqno.load(atomic::Ordering::Relaxed)
    }
    async fn save_seqno(&self, seqno: u64) -> Result<bool> {
        self.history.update(seqno, TARGET).await
    }

    #[cfg(feature = "telemetry")]
    fn add_metric(
        node: &AdnlNode, 
        peers: &AdnlPeers, 
        tag: &str, send: bool
    ) -> Arc<MetricBuilder> {
        let local = peers.local().to_string();
        let other = peers.other().to_string();
        let name = if send { 
            format!("{}->{} {}", &local[..6], &other[..6], tag)
        } else {
            format!("{}<-{} {}", &local[..6], &other[..6], tag)
        };
        let ret = MetricBuilder::with_metric_and_period(
            Metric::with_name_and_total(name.as_str()),
            AdnlNode::PERIOD_TELEMETRY_NANOS
        );
        node.telemetry.add_metric(TelemetryItem::MetricBuilder(ret.clone()));
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
    stop: Arc<AtomicU32>,
    transfers: Arc<lockfree::map::Map<TransferId, Arc<Transfer>>>,
    #[cfg(feature = "telemetry")]                                
    proc_load: Arc<Metric>,
    #[cfg(feature = "telemetry")]                                
    send_sock: Arc<MetricBuilder>,
    #[cfg(feature = "telemetry")]                                
    recv_sock: Arc<MetricBuilder>,
    #[cfg(feature = "telemetry")]                                
    recv_tmp1: Arc<Metric>,
    #[cfg(feature = "telemetry")]                                
    recv_tmp2: Arc<Metric>,
    #[cfg(feature = "telemetry")]                                
    recv_tmp3: Arc<Metric>,
    #[cfg(feature = "telemetry")]                                
    wait_recv: Arc<Metric>,
    #[cfg(feature = "telemetry")]                                
    wait_send: Arc<Metric>,
    #[cfg(feature = "telemetry")]
    telemetry: TelemetryPrinter
}

impl AdnlNode {

    const CLOCK_TOLERANCE: i32 = 60;         // Seconds
    const MAX_ADNL_MESSAGE: usize = 1024;
    const MAX_MESSAGES_IN_PROGRESS: u32 = 512;
    const SIZE_BUFFER: usize = 2048;
    const TIMEOUT_ADDRESS: i32 = 1000;       // Seconds
    const TIMEOUT_CHANNEL_RESET: u32 = 30;   // Seconds
    const TIMEOUT_QUERY_MIN: u64 = 500;      // Milliseconds
    const TIMEOUT_QUERY_MAX: u64 = 5000;     // Milliseconds
    const TIMEOUT_QUERY_STOP: u64 = 1;       // Milliseconds
    const TIMEOUT_SHUTDOWN: u64 = 2000;      // Milliseconds
    const TIMEOUT_TRANSFER: u64 = 3;         // Seconds
    #[cfg(feature = "telemetry")]
    const TIMEOUT_TELEMETRY: u64 = 5;        // Seconds
    #[cfg(feature = "telemetry")]
    const PERIOD_TELEMETRY_NANOS: u64 = 1000000;    

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
        #[cfg(feature = "telemetry")]
        let mut metrics = Vec::new();
        #[cfg(feature = "telemetry")]
        let proc_load = Metric::with_name("requests in progress, #");
        #[cfg(feature = "telemetry")]
        let send_sock = MetricBuilder::with_metric_and_period(
            Metric::with_name_and_total("socket send, packets/ms"),
            Self::PERIOD_TELEMETRY_NANOS
        );
        #[cfg(feature = "telemetry")]
        let recv_sock = MetricBuilder::with_metric_and_period(
            Metric::with_name_and_total("socket recv, packets/ms"),
            Self::PERIOD_TELEMETRY_NANOS
        );
        #[cfg(feature = "telemetry")]
        let recv_tmp1 = Metric::with_name_and_total("peer recv 1, packets");
        #[cfg(feature = "telemetry")]
        let recv_tmp2 = Metric::with_name_and_total("peer recv 2, packets");
        #[cfg(feature = "telemetry")]
        let recv_tmp3 = Metric::with_name_and_total("peer recv 3, packets");
        #[cfg(feature = "telemetry")]
        let wait_recv = Metric::with_name("socket recv wait, ns");
        #[cfg(feature = "telemetry")]
        let wait_send = Metric::with_name("throttling time, ns");
        #[cfg(feature = "telemetry")] {
            metrics.push(TelemetryItem::MetricBuilder(send_sock.clone()));
            metrics.push(TelemetryItem::MetricBuilder(recv_sock.clone()));
            metrics.push(TelemetryItem::Metric(proc_load.clone()));
            metrics.push(TelemetryItem::Metric(recv_tmp1.clone()));
            metrics.push(TelemetryItem::Metric(recv_tmp2.clone()));
            metrics.push(TelemetryItem::Metric(recv_tmp3.clone()));
            metrics.push(TelemetryItem::Metric(wait_recv.clone()));
//            metrics.push(wait_send.clone());
        }
        let ret = Self {
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
            stop: Arc::new(AtomicU32::new(0)),
            transfers: Arc::new(lockfree::map::Map::new()),
            #[cfg(feature = "telemetry")]
            proc_load,
            #[cfg(feature = "telemetry")]
            send_sock,
            #[cfg(feature = "telemetry")]
            recv_sock,
            #[cfg(feature = "telemetry")]
            recv_tmp1,
            #[cfg(feature = "telemetry")]
            recv_tmp2,
            #[cfg(feature = "telemetry")]
            recv_tmp3,
            #[cfg(feature = "telemetry")]
            wait_recv,
            #[cfg(feature = "telemetry")]
            wait_send,
            #[cfg(feature = "telemetry")]
            telemetry: TelemetryPrinter::with_params(Self::TIMEOUT_TELEMETRY, metrics)
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
/*
        let socket_send = tokio::net::UdpSocket::bind(
            &SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED), 
                node.config.ip_address.port()
            )
        ).await?;
        let socket_send = Arc::new(socket_send);
*/
        subscribers.push(Arc::new(AdnlPingSubscriber));
        // Subscribers poll
        let start = Arc::new(Instant::now());
        let subscribers = Arc::new(subscribers);
        let subscribers_local = subscribers.clone();
        for subscriber in subscribers.iter() {
            let node_subs = node.clone();
            let start = start.clone();
            let subscriber = subscriber.clone();
            tokio::spawn(
                async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
                        if node_subs.stop.load(atomic::Ordering::Relaxed) > 0 {      
                            break
                        }  
                        subscriber.poll(&start).await;
                    }
                }
            );
        }
        // Stopping watchdog
        let node_stop = node.clone();
        tokio::spawn(
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
                    #[cfg(feature = "telemetry")] 
                    node_stop.telemetry.try_print();
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
        // Remote connections
        let node_recv = node.clone();
//        let socket_recv = socket_send.clone();
        let (queue_recv_sender, queue_recv_reader) = mpsc::channel();
        let queue_recv_sent = Arc::new(AtomicU64::new(0));
        let queue_recv_read = queue_recv_sent.clone();
        thread::spawn(
            move || {
                let mut buf_src = None;
                loop {
                    if node_recv.stop.load(atomic::Ordering::Relaxed) > 0 {
                        break
                    }
                    let buf = buf_src.get_or_insert_with(
                        || {
                            let mut buf = Vec::with_capacity(Self::SIZE_BUFFER);
                            buf.resize(Self::SIZE_BUFFER, 0);
                            buf                                                       
                        }
                    );
                    #[cfg(feature = "telemetry")]
                    let start = Instant::now();
                    let len = match socket_recv.recv(&mut buf[..]) {
                        Ok(len) => len,
                        Err(err) => {
                            match err.kind() {
                                ErrorKind::WouldBlock => thread::yield_now(),
                                _ => log::warn!(target: TARGET, "ERROR <-- {}", err)
                            }
                            continue
                        }
                    };
                    #[cfg(feature = "telemetry")]
                    if start.elapsed().as_millis() < 1000 {
                        node_recv.wait_recv.update(start.elapsed().as_nanos() as u64);
                    }
                    #[cfg(feature = "telemetry")]
                    node_recv.recv_sock.update(1);
                    if len == 0 {
                        continue;
                    }
                    let mut buf = if let Some(buf) = buf_src.take() {
                        buf
                    } else {
                        continue
                    };
                    buf.truncate(len);
                    if let Err(e) = queue_recv_sender.send(buf) {
                        log::error!(target: TARGET, "ERROR in recv queue {}", e);
                    } else {
                        queue_recv_sent.fetch_add(1, atomic::Ordering::Relaxed);
                    }  
                }
                queue_recv_sent.fetch_add(1, atomic::Ordering::Relaxed)
            }
        );
        let node_recv = node.clone();
        tokio::spawn(
            async move {
                let proc_load = Arc::new(AtomicU32::new(0));
                loop {
                    if queue_recv_read.load(atomic::Ordering::Relaxed) == 0 {
                        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
//                        tokio::task::yield_now().await;
                        continue
                    }
                    let current_load = proc_load.load(atomic::Ordering::Relaxed);
                    #[cfg(feature = "telemetry")]
                    node_recv.proc_load.update(current_load as u64);
                    if current_load > Self::MAX_MESSAGES_IN_PROGRESS {
                        tokio::task::yield_now().await;
                        continue
                    }
                    let mut buf = match queue_recv_reader.recv() {
                        Ok(buf) => buf,
                        Err(_) => break
                    };
                    queue_recv_read.fetch_sub(1, atomic::Ordering::Relaxed);
                    let node_recv = node_recv.clone();
                    let proc_load = proc_load.clone();
                    let subscribers = subscribers.clone();
                    proc_load.fetch_add(1, atomic::Ordering::Relaxed);
                    tokio::spawn (
                        async move {
                            if let Err(e) = node_recv.receive(&mut buf, &subscribers).await {
                                log::warn!(target: TARGET, "ERROR <-- {}", e)
                            }
                            proc_load.fetch_sub(1, atomic::Ordering::Relaxed);
                        }
                    );
/*
                let mut buf_source = None;
                'recv: loop {            
                    let buf = buf_source.get_or_insert_with(
                        || {
                            let mut buf = Vec::with_capacity(Self::SIZE_BUFFER);
                            buf.resize(Self::SIZE_BUFFER, 0);
                            buf                                                       
                        }
                    );
                    #[cfg(feature = "telemetry")]
                    let start = Instant::now();
                    let len = loop {
                        if node_recv.stop.load(atomic::Ordering::Relaxed) > 0 {
                            break 'recv
                        }
                        match socket_recv.recv(&mut buf[..]) {
                            Ok(size) => break size,
                            Err(err) => match err.kind() {
                                std::io::ErrorKind::WouldBlock => {
                                    tokio::task::yield_now().await;
                                    continue
                                },
                                _ => {
                                    log::warn!(target: TARGET, "ERROR <-- {}", err);
                                    continue 'recv
                                }
                            }
                        }
                    };
  //                  let res = socket_recv.recv_from(&mut buf[..]).await;
                    #[cfg(feature = "telemetry")]
                    if start.elapsed().as_millis() < 2 {
                        node_recv.wait_recv.update(start.elapsed().as_nanos() as u64);
                    }
                    if len == 0 {
                        continue
                    }
//                    if node_recv.stop.load(atomic::Ordering::Relaxed) > 0 {
//                        break
//                    }
//                    let len = match res {
//                        Err(e) => {
//                            log::warn!(target: TARGET, "ERROR <-- {}", e);
//                            continue
//                        },
//                        Ok((len, _)) => len
//                    };
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
*/
                }
                node_recv.stop.fetch_add(1, atomic::Ordering::Relaxed);
                log::warn!(target: TARGET, "Node socket receiver exited");
            }
        );
        let node_send = node.clone();
        tokio::spawn(
            async move {
                const PERIOD_NANOS: u64 = 1000000;
                let start = Instant::now();
                let mut history = None;
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
                    // Manage the throughput
                    if let Some(throughput) = &node_send.config.throughput {
                        #[cfg(feature = "telemetry")]
                        let wait_start = start.elapsed().as_nanos();
                        let history = history.get_or_insert_with(
                            || VecDeque::with_capacity(*throughput as usize)
                        );
                        if history.len() >= *throughput as usize {
                            if let Some(time) = history.pop_front() {
                                while start.elapsed().as_nanos() - time < (PERIOD_NANOS as u128) {
                                    tokio::task::yield_now().await
                                }
                            }
                        }
                        history.push_back(start.elapsed().as_nanos());
                        #[cfg(feature = "telemetry")]
                        node_send.wait_send.update(
                            (start.elapsed().as_nanos() - wait_start) as u64
                        );
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
                                    tokio::task::yield_now().await;
                                    continue
                                },
                                _ => log::error!(target: TARGET, "ERROR --> {}", err)
                            }
                        }
                        break
                    }
//                    if let Err(e) = sender.send_to(&job.data[..], &addr).await {
//                        log::error!(target: TARGET, "ERROR --> {}", e);
//                    }
                    #[cfg(feature = "telemetry")]
                    node_send.send_sock.update(1);
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
            tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
            if self.stop.load(atomic::Ordering::Relaxed) >= 5 {
                break
            }
        }
        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_SHUTDOWN)).await;
        log::warn!(target: TARGET, "ADNL node stopped");
    }

    /// Add key
    pub fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
        let ret = self.config.add_key(key, tag)?;
        add_object_to_map(
            &self.peers,
            ret.clone(),
            || Ok(Arc::new(lockfree::map::Map::new()))
        )?;
        Ok(ret)
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
                    Ok(address) => {
                        #[cfg(feature = "telemetry")]
                        let peers = AdnlPeers::with_keys(local_key.clone(), ret.clone());
                        lockfree::map::Preview::New(
                            Peer {
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
                                )
                            }
                        )
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
log::info!(target: TARGET, "Sent query {:02x}{:02x}{:02x}{:02x}", query_id[0], query_id[1], query_id[2], query_id[3]);
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
log::info!(target: TARGET, "Scheduling drop for query {:02x}{:02x}{:02x}{:02x} in {} ms", query_id[0], query_id[1], query_id[2], query_id[3], timeout);
                tokio::time::sleep(Duration::from_millis(timeout)).await;
log::info!(target: TARGET, "Try dropping query {:02x}{:02x}{:02x}{:02x}", query_id[0], query_id[1], query_id[2], query_id[3]);
                match Self::update_query(&queries, query_id, None).await {
                    Err(e) => 
log::info!(target: TARGET, "ERROR: {} when dropping query {:02x}{:02x}{:02x}{:02x}", e, query_id[0], query_id[1], query_id[2], query_id[3]),
                    Ok(true) => 
log::info!(target: TARGET, "Dropped query {:02x}{:02x}{:02x}{:02x}", query_id[0], query_id[1], query_id[2], query_id[3]),
                    _ => ()
                }
            }
        );
        ping.wait().await;                     
log::info!(target: TARGET, "Finished query {:02x}{:02x}{:02x}{:02x}", query_id[0], query_id[1], query_id[2], query_id[3]);
        if let Some(removed) = self.queries.remove(&query_id) {
            match removed.val() {
                Query::Received(answer) => 
                    return Ok(Some(deserialize(answer)?)),
                Query::Timeout => {
                    /* Monitor channel health */
                    if let Some(channel) = channel {
                        let now = Version::get() as u32;
                        let was = channel.val().drop.compare_exchange(
                            0,
                            now + Self::TIMEOUT_CHANNEL_RESET,
                            atomic::Ordering::Relaxed,
                            atomic::Ordering::Relaxed
                        ).unwrap_or_else(|was| was);
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
                            )
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
    ) -> Result<Option<Arc<KeyId>>> {
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
            match peer.recv_state.save_seqno(*seqno as u64).await {
                Err(e) => fail!("Peer {} ({:?}): {}", ret, other_key, e),
                Ok(false) => return Ok(None),
                _ => ()
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
        peers: &AdnlPeers
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
                                tokio::time::sleep(
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
        #[cfg(feature = "telemetry")]
        let received_len = buf.len();
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
            log::trace!(
                target: TARGET,
                "Received message to unknown key ID {}", 
                base64::encode(&buf[0..32])
            );
            return Ok(())
        };
        #[cfg(feature = "telemetry")]
        self.recv_tmp1.update(1);
        let pkt = deserialize(&buf[..])?
            .downcast::<AdnlPacketContents>()
            .map_err(|pkt| failure::format_err!("Unsupported ADNL packet format {:?}", pkt))?;
        let other_key = if let Some(key) = self.check_packet(&pkt, &local_key, other_key).await? {
            key
        } else {
            #[cfg(feature = "telemetry")]
            self.recv_tmp2.update(1);
            return Ok(())
        };
        #[cfg(feature = "telemetry")]
        self.recv_tmp3.update(1);
        #[cfg(feature = "telemetry")]
        if let Some(peer) = self.peers(&local_key)?.get(&other_key) {
            peer.val().update_recv_stats(received_len as u64, &local_key)
        }
        let peers = AdnlPeers::with_keys(local_key, other_key);
        if let Some(msg) = pkt.message() { 
            self.process(
                subscribers, 
                msg, 
                &peers 
            ).await?
        } else if let Some(msgs) = pkt.messages() {
            for msg in msgs.deref() {
                self.process(
                    subscribers, 
                    msg, 
                    &peers
                ).await?;
            }
        } else {
            // Specifics of implementation. 
            // Address/seqno update is to be sent serarately from data
            // fail!("ADNL packet ({}) without a message: {:?}", buf.len(), pkt)
        }
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
        #[cfg(feature = "telemetry")]
        peer.update_send_stats(data.len() as u64, source.id());
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
        let mut received = transfer.received.compare_exchange(
            transfer.total, 
            2 * transfer.total, 
            atomic::Ordering::Relaxed,
            atomic::Ordering::Relaxed
        ).unwrap_or_else(|was| was);
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
