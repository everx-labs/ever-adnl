use crate::{
    from_slice, 
    common::{
        add_object_to_map, AdnlCryptoUtils, AdnlHandshake, AdnlPeers, AdnlPingSubscriber, 
        deserialize, get256, hash, KeyId, KeyOption, KeyOptionJson, Query, QueryCache, 
        QueryId, serialize, Subscriber, TARGET, UpdatedAt, Version
    }
};
use aes_ctr::stream_cipher::SyncStreamCipher;
use core::sync::atomic::{self, AtomicI32, AtomicU32, AtomicU64, AtomicUsize};
use rand::Rng;
use sha2::Digest;
use std::{
    cmp::{min, Ordering}, fmt::{self, Debug, Display, Formatter}, 
    net::{IpAddr, Ipv4Addr, SocketAddr}, ops::Deref, sync::Arc, time::Duration
};
use ton_api::{
    IntoBoxed, 
    ton::{
        self, TLObject,  
        adnl::{
            Address, Message as AdnlMessage, PacketContents as AdnlPacketContents, 
            address::address::Udp, addresslist::AddressList, id::short::Short as AdnlIdShort,  
            message::message::{ConfirmChannel, CreateChannel, Custom as AdnlCustomMessage}, 
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
        self.find_by_index({*index += 1; *index})
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

    pub fn random(&self) -> Option<Arc<KeyId>> {
        let max = self.count();
        if let Some(ret) = self.index.get(&rand::thread_rng().gen_range(0, max)) {
            Some(ret.val().clone())
        } else {
            None
        }
    }

    pub fn random_set(&self, dst: &AddressCache, mut n: u32) -> Result<()> {
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
        let ret = Self {
            channel_key: Arc::new(KeyOption::with_type_id(key.type_id())?),
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
    pub fn from_ip_address_and_key(
        ip_address: &str, 
        key: KeyOption,
        tag: usize
    ) -> Result<Self> {
        let tags = lockfree::map::Map::new();
        let keys = lockfree::map::Map::new();
        let data = Arc::new(key);
        tags.insert(tag, data.id().clone());
        keys.insert(data.id().clone(), data);
        let ret = AdnlNodeConfig {
            ip_address: IpAddress::from_string(ip_address)?,
            tags,
            keys
        };
        Ok(ret)
    }    

    /// Construct from JSON data 
    pub fn from_json(json: &str, as_src: bool) -> Result<Self> {
        let json_config: AdnlNodeConfigJson = serde_json::from_str(json)?;
        Self::from_json_config(&json_config, as_src)
    }

    /// Construct from JSON config structure
    pub fn from_json_config(json_config: &AdnlNodeConfigJson, as_src: bool) -> Result<Self> {
        let tags = lockfree::map::Map::new();
        let keys = lockfree::map::Map::new();
        for key in json_config.keys.iter() {
            let data = if as_src {
                KeyOption::from_private_key(&key.data)?
            } else {
                KeyOption::from_public_key(&key.data)?
            };
            let id = data.id().clone();
            if tags.insert(key.tag, id.clone()).is_some() {
                fail!("Duplicated key tag {} in node config", key.tag)
            }
            if keys.insert(id.clone(), Arc::new(data)).is_some() {
                fail!("Duplicated key {} in node config", id)
            }
        }
        let ret = AdnlNodeConfig {
            ip_address: json_config.ip_address()?,
            tags,
            keys
        };
        Ok(ret)
    }

    /// Construct with given IP address (new key pair will be generated)
    pub fn with_ip_address_and_key_type(
        ip_address: &str, 
        type_id: i32, 
        tag: usize
    ) -> Result<Self> {
        Self::from_ip_address_and_key(ip_address, KeyOption::with_type_id(type_id)?, tag)
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

struct Peer {
    address: AdnlNodeAddress,
    recv_state: PeerState,
    send_state: PeerState
}

struct PeerState {
    reinit_date: AtomicI32,
    seqno: AtomicU64,
    window: Option<AtomicU64>
}

impl PeerState {

    const WINDOW: i8 = 32;
    const MARKER: i8 = 64 - Self::WINDOW;

    fn for_receive_with_reinit_date(reinit_date: i32) -> Self {
        Self {
            reinit_date: AtomicI32::new(reinit_date),
            seqno: AtomicU64::new(0),
            window: Some(AtomicU64::new(0))
        }
    }

    fn for_send() -> Self {
        Self {
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
    fn reset_seqno(&self, seqno: u64) {
        self.seqno.store(seqno, atomic::Ordering::Relaxed);
        if let Some(window) = &self.window {
            window.store(seqno as u32 as u64, atomic::Ordering::Relaxed)
        }
    }
    fn seqno(&self) -> u64 {
        self.seqno.load(atomic::Ordering::Relaxed)
    }

    fn save_seqno(&self, seqno: u64) -> Result<()> {
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

}

#[derive(Debug)]
struct SendJob {
    destination: u64,
    data: Vec<u8>
}

struct Transfer {
    data: lockfree::map::Map<usize, Vec<u8>>,
    received: 	AtomicUsize,
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
    queue_sender: tokio::sync::mpsc::UnboundedSender<SendJob>,
    queue_reader: lockfree::queue::Queue<tokio::sync::mpsc::UnboundedReceiver<SendJob>>,
    start_time: i32,
    transfers: lockfree::map::Map<TransferId, Transfer>
}

impl AdnlNode {

    const CLOCK_TOLERANCE: i32 = 60;     // Seconds
    const MAX_QUERY_DROPS: u32 = 10;    
    const SIZE_BUFFER: usize = 2048;
    const TIMEOUT_ADDRESS: i32 = 1000;   // Seconds
    const TIMEOUT_QUERY_MIN: u64 = 500;  // Milliseconds
    const TIMEOUT_QUERY_MAX: u64 = 5000; // Milliseconds
    const TIMEOUT_TRANSFER: u64 = 3;     // Seconds

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
        let incinerator = lockfree::map::SharedIncin::new();
        let ret = Self {
            config, 
            channels_recv: Arc::new(lockfree::map::Map::new()), 
            channels_send: Arc::new(lockfree::map::Map::with_incin(incinerator.clone())), 
            channels_wait: Arc::new(lockfree::map::Map::with_incin(incinerator)), 
            peers,
            queries: Arc::new(lockfree::map::Map::new()), 
            queue_sender,
            queue_reader: lockfree::queue::Queue::new(),
            start_time: Version::get(),
            transfers: lockfree::map::Map::new()
        };
        ret.queue_reader.push(queue_reader);
        Ok(Arc::new(ret))
    }

    /// Start node 
    pub async fn start(
        node: &Arc<Self>, 
        mut subscribers: Vec<Arc<dyn Subscriber>>
    ) -> Result<()> {
        let mut queue_reader = if let Some(queue_reader) = node.queue_reader.pop() {
            queue_reader
        } else {
            fail!("ADNL node already started")
        };
        let (mut receiver, mut sender) = 
            tokio::net::UdpSocket::bind(
                &SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED), 
                    node.config.ip_address.port()
                )
            )
            .await?
            .split();
        let node = node.clone();
        subscribers.push(Arc::new(AdnlPingSubscriber));
        tokio::spawn(
            async move {
                let mut buf_source = None;
                let subscribers = Arc::new(subscribers);
                loop {            
                    let buf = buf_source.get_or_insert_with(
                        || {
                            let mut buf = Vec::with_capacity(Self::SIZE_BUFFER);
                            buf.resize(Self::SIZE_BUFFER, 0);
                            buf                                                       
                        }
                    );
                    let len = match receiver.recv_from(&mut buf[..]).await {
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
                    let node = node.clone();
                    let subscribers = subscribers.clone();
                    tokio::spawn (
                        async move {
                            if let Err(e) = node.receive(&mut buf, &subscribers).await {
                                log::warn!(target: TARGET, "ERROR <-- {}", e)
                            }
                        }
                    );
                }
            }
        );
        tokio::spawn(
            async move {
                while let Some(job) = queue_reader.recv().await {
                    if let Err(e) = Self::send(&mut sender, job).await {
                        log::warn!(target: TARGET, "ERROR --> {}", e);
                    }
                }
            }
        );
        Ok(())
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
    pub fn build_address_list(&self, reinit_date: i32) -> Result<AddressList> {
        let version = Version::get();
        let ret = AddressList {
            addrs: vec![self.config.ip_address.into_udp().into_boxed()].into(),
            version,
            reinit_date: if reinit_date == 0 {
                version
            } else {
                reinit_date
            },
            priority: 0,
            expire_at: version + Self::TIMEOUT_ADDRESS
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
            fail!("Address list version is too high")
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
        let channel = self.channels_send.get(peers.other());
        self.send_message(msg, peers)?;
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
                Query::Received(answer) => {
                    /* Restore channel health */
                    if let Some(channel) = channel {
                        channel.val().drop.store(0, atomic::Ordering::Relaxed)
                    }
                    return Ok(Some(deserialize(answer)?))
                },
                Query::Timeout => {
log::warn!("Dropped query {:02x}{:02x}{:02x}{:02x}", query_id[0], query_id[1], query_id[2], query_id[3]);
                    /* Monitor channel health */
                    if let Some(channel) = channel {
                        let drops = channel.val().drop.fetch_add(1, atomic::Ordering::Relaxed);
                        if drops >= Self::MAX_QUERY_DROPS {
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

    fn check_packet(
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
                        peer.send_state.reset_seqno(0);
                        peer.recv_state.reset_seqno(0);
                    }
                },
                Ordering::Less => 
                    fail!("Source reinit date is too old: {}", reinit_date)
            }
        }
        if let Some(seqno) = packet.seqno() {
            if let Err(e) = peer.recv_state.save_seqno(*seqno as u64) {
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
        peers: &AdnlPeers
    ) -> Result<()> {
        let new_msg = if let AdnlMessage::Adnl_Message_Part(part) = msg {
            add_object_to_map(
                &self.transfers,
                part.hash.0,
                || {
                    let transfer = Transfer {
                        data: lockfree::map::Map::new(),
                        received: AtomicUsize::new(0),
                        total: part.total_size as usize,
                        updated: UpdatedAt::new()
                    };
                    Ok(transfer)
                }
            )?;
            if let Some(transfer) = self.transfers.get(&part.hash.0) {
                let transfer = transfer.val();
                transfer.updated.refresh();
                transfer.data.insert(part.offset as usize, part.data.to_vec());
                transfer.received.fetch_add(part.data.len(), atomic::Ordering::Relaxed);
                match Self::update_transfer(transfer) {
                    Ok(Some(msg)) => {
                        self.transfers.remove(&part.hash.0);
                        Some(msg)
                    },
                    Err(error) => {
                        self.transfers.remove(&part.hash.0);
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
        let msg = if let Some(msg) = &new_msg {
            msg
        } else {
            msg
        };
        for transfer in self.transfers.iter() {
            if transfer.val().updated.is_expired(Self::TIMEOUT_TRANSFER) {
                self.transfers.remove(transfer.key());
                log::debug!(
                    target: TARGET, 
                    "ADNL transfer {} timed out",
                    base64::encode(transfer.key())
                );
            }
        }
        let msg = match msg {
            AdnlMessage::Adnl_Message_Answer(answer) => {
                let query_id = answer.query_id.0;
                if !Self::update_query(&self.queries, query_id, Some(&answer.answer)).await? {
                    fail!("Received answer from {} to unknown query {:?}", peers.other(), answer)
                }
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
                if let (true, answer) = Query::process_adnl(subscribers, query).await? {
                    answer
                } else {
                    fail!("No subscribers for query {:?}", query)
                }
            },
            _ => fail!("Unsupported ADNL message {:?}", msg)
        };
        if let Some(msg) = msg {
            self.send_message(msg, peers)?;
        }
        Ok(())
    }

    async fn receive(
        &self, 
        buf: &mut Vec<u8>,
        subscribers: &Vec<Arc<dyn Subscriber>>,
    ) -> Result<()> {
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
            (channel.local_key.clone(), Some(channel.other_key.clone()))
        } else {
            fail!("Received message to unknown key ID {}", base64::encode(&buf[0..32]))
        };
        let pkt = deserialize(&buf[..])?
            .downcast::<AdnlPacketContents>()
            .map_err(|pkt| failure::format_err!("Unsupported ADNL packet format {:?}", pkt))?;
        let other_key = self.check_packet(&pkt, &local_key, other_key)?;        
        let peers = AdnlPeers::with_keys(local_key, other_key);
        if let Some(msg) = pkt.message() { 
            self.process(subscribers, msg, &peers).await?
        } else if let Some(msgs) = pkt.messages() {
            for msg in msgs.deref() {
                self.process(subscribers, msg, &peers).await?;
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
        let (msg, msgs) = if channel.is_none() && self.channels_wait.get(dst).is_none() {
            let mut msgs = Vec::new();
            msgs.push(
                CreateChannel {
                    key: ton::int256(peer.address.channel_key.pub_key()?.clone()),
                    date: Version::get()
                }.into_boxed()
            );
            log::debug!(target: TARGET, "Create channel {} -> {}", src.id(), dst);
            msgs.push(msg);
            (None, Some(msgs))
        } else {
            (Some(msg), None)
        };
        let mut data = serialize(
            &PacketContents {
                rand1: ton::bytes(Self::gen_rand()),
                from: if channel.is_some() {
                    None
                } else {
                    Some(src.into_tl_public_key()?)
                },
                from_short: if channel.is_some() {
                    None
                } else {
                    Some(
                        AdnlIdShort {
                            id: ton::int256(src.id().data().clone())
                        }
                    )
                }, 
                message: msg,
                messages: if let Some(msgs) = msgs {
                    Some(msgs.into())
                } else {
                    None
                },
                address: Some(
                    self.build_address_list(peer.recv_state.reinit_date())?
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
            channel.val().encrypt(&mut data)?
        } else {
            let key = KeyOption::with_type_id(src.type_id())?;
            AdnlHandshake::build_packet(&mut data, &key, &peer.address.key)?;
        }
        let job = SendJob { 
            destination: peer.address.ip_address.load(atomic::Ordering::Relaxed),
            data
        };
        self.queue_sender.send(job)?;
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

    fn update_transfer(transfer: &Transfer) -> Result<Option<AdnlMessage>> {
        let mut received = transfer.received.load(atomic::Ordering::Relaxed);
        if received > transfer.total {
            fail!("Invalid ADNL part transfer: size mismatch")
        }
        if received == transfer.total {
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
            let msg = deserialize(&buf[..])?
                .downcast::<AdnlMessage>()
                .map_err(|msg| failure::format_err!("Unsupported ADNL messge {:?}", msg))?;
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

}
                        	