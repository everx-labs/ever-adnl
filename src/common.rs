use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use core::ops::Range;
use ed25519::signature::{Signature, Verifier};
use rand::Rng;
use sha2::Digest;
use std::{
    fmt::{self, Debug, Display, Formatter}, hash::Hash,
    sync::{Arc, atomic::{AtomicU64, AtomicUsize, Ordering}},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH}
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ton_api::{
    BoxedSerialize, Deserializer, IntoBoxed, Serializer, 
    ton::{
        self, TLObject, 
        adnl::{
            Message as AdnlMessage, 
            message::message::{
                Answer as AdnlAnswerMessage, Custom as AdnlCustomMessage, 
                Query as AdnlQueryMessage 
            },
            pong::Pong as AdnlPong
        },
        pub_::publickey::Ed25519,
        rldp::message::{Answer as RldpAnswer, Query as RldpQuery},
        rpc::adnl::Ping as AdnlPing
    }
};
use ton_types::{fail, Result};

#[cfg(any(feature = "client", feature = "node", feature = "server"))]
pub(crate) const TARGET: &str = "adnl";

#[macro_export]
macro_rules! dump {
    ($data: expr) => {
        {
            let mut dump = String::new();
            for i in 0..$data.len() {
                dump.push_str(
                    &format!(
                        "{:02x}{}", 
                        $data[i], 
                        if (i + 1) % 16 == 0 { '\n' } else { ' ' }
                    )
                )
            }
            dump
        }
    };
    (debug, $target:expr, $msg:expr, $data:expr) => {
        if log::log_enabled!(log::Level::Debug) {
            log::debug!(target: $target, "{}:\n{}", $msg, dump!($data))
        }
    };
    (trace, $target:expr, $msg:expr, $data:expr) => {
        if log::log_enabled!(log::Level::Trace) {
            log::trace!(target: $target, "{}:\n{}", $msg, dump!($data))
        }
    }
}

#[macro_export]
macro_rules! from_slice {
    ($x:ident, 32) => {
         [ 
             $x[ 0], $x[ 1], $x[ 2], $x[ 3], $x[ 4], $x[ 5], $x[ 6], $x[ 7], $x[ 8], $x[ 9], 
             $x[10], $x[11], $x[12], $x[13], $x[14], $x[15], $x[16], $x[17], $x[18], $x[19], 
             $x[20], $x[21], $x[22], $x[23], $x[24], $x[25], $x[26], $x[27], $x[28], $x[29], 
             $x[30], $x[31]
         ]
    };
    ($x:ident, $ix:expr, 16, $y: ident, $iy:expr, 16) => {
         [ 
             $x[$ix +  0], $x[$ix +  1], $x[$ix +  2], $x[$ix +  3], $x[$ix +  4], $x[$ix +  5], 
             $x[$ix +  6], $x[$ix +  7], $x[$ix +  8], $x[$ix +  9], $x[$ix + 10], $x[$ix + 11], 
             $x[$ix + 12], $x[$ix + 13], $x[$ix + 14], $x[$ix + 15], 
             $y[$iy +  0], $y[$iy +  1], $y[$iy +  2], $y[$iy +  3], $y[$iy +  4], $y[$iy +  5], 
             $y[$iy +  6], $y[$iy +  7], $y[$iy +  8], $y[$iy +  9], $y[$iy + 10], $y[$iy + 11], 
             $y[$iy + 12], $y[$iy + 13], $y[$iy + 14], $y[$iy + 15], 
         ]
    };
    ($x:ident, $ix:expr, 4, $y: ident, $iy:expr, 12) => {
         [ 
             $x[$ix +  0], $x[$ix +  1], $x[$ix +  2], $x[$ix +  3], 
             $y[$iy +  0], $y[$iy +  1], $y[$iy +  2], $y[$iy +  3], $y[$iy +  4], $y[$iy +  5], 
             $y[$iy +  6], $y[$iy +  7], $y[$iy +  8], $y[$iy +  9], $y[$iy + 10], $y[$iy + 11], 
         ]
    }
}

#[macro_export]
macro_rules! trace {
    ($target:expr, $func:expr) => {
        {
            if log::log_enabled!(log::Level::Debug) {
                let msg = stringify!($func);
                let pos = msg.find('\n').unwrap_or(80);
                log::debug!(target: $target, "before {}...", &msg[..pos]);
                let ret = $func;
                log::debug!(target: $target, "after {}...", &msg[..pos]);
                ret
            } else {
                $func
            }
        }
    };
}

/// ADNL crypto utils
pub struct AdnlCryptoUtils;

impl AdnlCryptoUtils {

    /// Build AES-based cipher with clearing key data
    pub fn build_cipher_secure(key: &mut [u8], ctr: &mut [u8]) -> aes_ctr::Aes256Ctr {
        let ret = Self::build_cipher_internal(key, ctr);
        key.iter_mut().for_each(|a| *a = 0);
        ctr.iter_mut().for_each(|a| *a = 0);
        ret
    }

    /// Build AES-based cipher without clearing key data
    pub fn build_cipher_unsecure(
        nonce: &[u8; 160], 
        range_key: Range<usize>, 
        range_ctr: Range<usize>
    ) -> aes_ctr::Aes256Ctr {
        Self::build_cipher_internal(&nonce[range_key], &nonce[range_ctr])
    }

    /// Calculate shared secret
    pub fn calc_shared_secret(pvt_key: &[u8; 32], pub_key: &[u8; 32]) -> [u8; 32] {
        let point = curve25519_dalek::edwards::CompressedEdwardsY(*pub_key)
            .decompress()
            .expect("Bad public key data")
            .to_montgomery()
            .to_bytes();
        x25519_dalek::x25519(*pvt_key, point)
    }
    
    fn build_cipher_internal(key: &[u8], ctr: &[u8]) -> aes_ctr::Aes256Ctr {
        aes_ctr::Aes256Ctr::new(
            aes_ctr::stream_cipher::generic_array::GenericArray::from_slice(key), 
            aes_ctr::stream_cipher::generic_array::GenericArray::from_slice(ctr) 
        )
    }

}

/// ADNL handshake
pub struct AdnlHandshake;

impl AdnlHandshake {

    /// Build handshake packet
    #[cfg(any(feature = "client", feature = "node"))]
    pub fn build_packet(
        buf: &mut Vec<u8>, 
        local: &KeyOption, 
        other: &KeyOption
    ) -> Result<()> {

        let checksum = {
            let checksum = sha2::Sha256::digest(&buf[..]);
            let checksum = checksum.as_slice();
            from_slice!(checksum, 32)
        };

        let len = buf.len();
        buf.resize(len + 96, 0);
        buf[..].copy_within(..len, 96);                                                         
        buf[..32].copy_from_slice(other.id().data());
        buf[32..64].copy_from_slice(local.pub_key()?);
        buf[64..96].copy_from_slice(&checksum);

        let mut shared_secret = AdnlCryptoUtils::calc_shared_secret(
            local.pvt_key()?, 
            other.pub_key()?
        );
        dump!(trace, TARGET, "Shared Secret", &shared_secret);
        Self::build_packet_cipher(&mut shared_secret, &checksum)
            .apply_keystream(&mut buf[96..]);
        Ok(())

    }

    /// Parse handshake packet
    #[cfg(any(feature = "server", feature = "node"))]
    pub fn parse_packet(
        keys: &lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>, 
        buf: &mut Vec<u8>, 
        len: Option<usize>
    ) -> Result<Option<Arc<KeyId>>> {
        if buf.len() < 96 + len.unwrap_or(0) {
            fail!("Bad handshake packet length: {}", buf.len());
        }
        for key in keys.iter() {
            if key.val().id().data().eq(&buf[0..32]) {
                let mut shared_secret = AdnlCryptoUtils::calc_shared_secret(
                    key.val().pvt_key()?, 
                    arrayref::array_ref!(buf, 32, 32)
                );
                dump!(trace, TARGET, "Shared Secret", &shared_secret);
                let range = if let Some(len) = len {
                    96..96 + len
                } else {
                    96..buf.len()
                };
                Self::build_packet_cipher(&mut shared_secret, arrayref::array_ref!(buf, 64, 32))
                    .apply_keystream(&mut buf[range]);
                if !sha2::Sha256::digest(&buf[96..]).as_slice().eq(&buf[64..96]) {
                    fail!("Bad handshake packet checksum");
                }
                buf.drain(0..96);
                return Ok(Some(key.key().clone()));
            }
        }
        Ok(None)
    }

    #[cfg(any(feature = "client", feature = "server", feature = "node"))]
    fn build_packet_cipher(
        shared_secret: &mut [u8; 32], 
        checksum: &[u8; 32]
    ) -> aes_ctr::Aes256Ctr {
        let x = &shared_secret[..];
        let y = &checksum[..];
        let mut aes_key_bytes = from_slice!(x, 0, 16, y, 16, 16);
        let mut aes_ctr_bytes = from_slice!(y, 0,  4, x, 20, 12);
        dump!(trace, TARGET, "AES-Ctr Key (handshake)", &aes_key_bytes);
        dump!(trace, TARGET, "AES-Ctr Counter (handshake)", &aes_ctr_bytes);
        shared_secret.iter_mut().for_each(|a| *a = 0);
        AdnlCryptoUtils::build_cipher_secure(&mut aes_key_bytes, &mut aes_ctr_bytes)
    }

}

/// ADNL peers
#[derive(Clone)]
pub struct AdnlPeers(Arc<KeyId>, Arc<KeyId>);

impl AdnlPeers {

    /// Constructor
    pub fn with_keys(local: Arc<KeyId>, other: Arc<KeyId>) -> Self {
        Self(local, other)
    }

    /// Local peer
    pub fn local(&self) -> &Arc<KeyId> {
        let AdnlPeers(local, _) = self;
        local 
    }

    /// Other peer
    pub fn other(&self) -> &Arc<KeyId> {
        let AdnlPeers(_, other) = self;
        other 
    }

    /// Change other peer
    pub fn set_other(&mut self, other: Arc<KeyId>) {
        let AdnlPeers(_, old_other) = self;
        *old_other = other
    }

}

/// ADNL ping subscriber
pub struct AdnlPingSubscriber;

#[async_trait::async_trait]
impl Subscriber for AdnlPingSubscriber {
    async fn try_consume_query(
        &self, 
        object: TLObject, 
        _peers: &AdnlPeers
    ) -> Result<QueryResult> {
        match object.downcast::<AdnlPing>() {
            Ok(ping) => QueryResult::consume(AdnlPong { value: ping.value }),
            Err(object) => Ok(QueryResult::Rejected(object))
        }
    }
}

/// ADNL TCP stream                      
pub struct AdnlStream(tokio_io_timeout::TimeoutStream<tokio::net::TcpStream>);

impl AdnlStream {
    /// Constructor
    pub fn from_stream_with_timeouts(stream: tokio::net::TcpStream, timeouts: &Timeouts) -> Self {
        let mut stream = tokio_io_timeout::TimeoutStream::new(stream);
        stream.set_write_timeout(timeouts.write());
        stream.set_read_timeout(timeouts.read());
        Self(stream)
    }
    /// Read from stream
    pub async fn read(&mut self, buf: &mut Vec<u8>, len: usize) -> Result<()> {
        buf.resize(len, 0);
        let Self(stream) = self;
        stream.get_mut().read_exact(&mut buf[..]).await?;
        Ok(())
    }
    /// Shutdown stream
    pub async fn shutdown(&mut self) -> Result<()> {
        let Self(stream) = self;       
        stream.get_mut().shutdown().await?;
        Ok(())
    }
    /// Write to stream
    pub async fn write(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        let Self(stream) = self;
        stream.get_mut().write_all(&buf[..]).await?;
        buf.truncate(0);
        Ok(())
    }
}

/// ADNL stream cryptographic context
pub struct AdnlStreamCrypto {
    cipher_recv: aes_ctr::Aes256Ctr,
    cipher_send: aes_ctr::Aes256Ctr
}

impl AdnlStreamCrypto {

    /// Construct as client
    #[cfg(feature = "client")]
    pub fn with_nonce_as_client(nonce: &[u8; 160]) -> Self {
        /* Do not clear nonce because it will be encrypted inplace afterwards */
        Self {
            cipher_recv: AdnlCryptoUtils::build_cipher_unsecure(nonce,  0..32, 64..80),
            cipher_send: AdnlCryptoUtils::build_cipher_unsecure(nonce, 32..64, 80..96)
        }
    }

    /// Construct as server
    #[cfg(feature = "server")]
    pub fn with_nonce_as_server(nonce: &mut [u8; 160]) -> Self {
        /* Clear nonce */
        let ret = Self {
            cipher_recv: AdnlCryptoUtils::build_cipher_unsecure(nonce, 32..64, 80..96),
            cipher_send: AdnlCryptoUtils::build_cipher_unsecure(nonce,  0..32, 64..80)
        };
        nonce.iter_mut().for_each(|a| *a = 0);
        ret
    }

    /// Send data in-place
    pub async fn send(&mut self, stream: &mut AdnlStream, buf: &mut Vec<u8>) -> Result<()> {
        let nonce: [u8; 32] = rand::thread_rng().gen();
        let len = buf.len();
        buf.reserve(len + 68);
        buf.resize(len + 36, 0);
        buf[..].copy_within(..len, 36);
        buf[..4].copy_from_slice(&((len + 64) as u32).to_le_bytes());
        buf[4..36].copy_from_slice(&nonce);   
        buf.extend_from_slice(sha2::Sha256::digest(&buf[4..]).as_slice());
        self.cipher_send.apply_keystream(&mut buf[..]);      
        stream.write(buf).await?;
        Ok(())
    }

    /// Receive data
    pub async fn receive(&mut self, buf: &mut Vec<u8>, stream: &mut AdnlStream) -> Result<()> {
        stream.read(buf, 4).await?;
        self.cipher_recv.apply_keystream(&mut buf[..4]);      
        let length = u32::from_le_bytes([ buf[0], buf[1], buf[2], buf[3] ]) as usize;
        if length < 64 {
            fail!("Too small size for ANDL packet: {}", length);
        }
        stream.read(buf, length).await?;
        self.cipher_recv.apply_keystream(&mut buf[..length]);        
        if !sha2::Sha256::digest(&buf[..length - 32]).as_slice().eq(&buf[length - 32..length]) {
            fail!("Bad checksum for ANDL packet");
        }
        buf.truncate(length - 32);
        buf.drain(..32);
        Ok(())
    }

}

/// ADNL/RLDP answer
pub enum Answer {
    Object(TLObject),
    Raw(Vec<u8>)
}

/// ADNL key ID (node ID)
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct KeyId([u8; 32]);

impl KeyId {
   pub fn from_data(data: [u8; 32]) -> Arc<Self> {
       Arc::new(Self(data))
   }
   pub fn data(&self) -> &[u8; 32] {
       &self.0
   }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", base64::encode(self.data()))
    }
}

/// ADNL server/node key option
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyOption {
    id: Arc<KeyId>,
    keys: [Option<[u8; 32]>; 3], // public(0) private-lo(1) private-hi(2) keys
    type_id: i32
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct KeyOptionJson {
    type_id: i32,
    pub_key: Option<String>,
    pvt_key: Option<String>
}

impl KeyOption {

    pub const KEY_ED25519: i32 = 1209251014;

    /// Create from Ed25519 expanded secret key
    pub fn from_ed25519_expanded_secret_key(exp_key: ed25519_dalek::ExpandedSecretKey) -> Self {
        let pub_key = ed25519_dalek::PublicKey::from(&exp_key).to_bytes();
        let exp_key = &exp_key.to_bytes();
        let pvt_key = &exp_key[..32];
        let pvt_key = from_slice!(pvt_key, 32);
        let exp_key = &exp_key[32..];
        let exp_key = from_slice!(exp_key, 32);
        Self {
            id: Self::calc_id(Self::KEY_ED25519, &pub_key), 
            keys: [Some(pub_key), Some(pvt_key), Some(exp_key)],
            type_id: Self::KEY_ED25519
        }
    }

    /// Create from Ed25519 secret key
    pub fn from_ed25519_secret_key(key: ed25519_dalek::SecretKey) -> Self {
        Self::from_ed25519_expanded_secret_key(ed25519_dalek::ExpandedSecretKey::from(&key))
    }

    /// Create from private key 
    pub fn from_private_key(src: &KeyOptionJson) -> Result<Self> {
        if src.pub_key.is_some() {
            fail!("No public key expected");
        };
        let key = if let Some(key) = &src.pvt_key {
            base64::decode(key)?
        } else {
            fail!("No private key");
        };
        if key.len() != 32 {
            fail!("Bad private key");
        } 
        if src.type_id == Self::KEY_ED25519 {
            let sec_key = ed25519_dalek::SecretKey::from_bytes(&key[..32])?;
            Ok(Self::from_ed25519_secret_key(sec_key))
        } else {
            fail!("Type-id {} is not supported for private key", src.type_id);
        }
    }

    /// Create from public key 
    pub fn from_public_key(src: &KeyOptionJson) -> Result<Self> {
        if src.pvt_key.is_some() {
            fail!("No private key expected");
        };
        let key = if let Some(key) = &src.pub_key {
            base64::decode(key)?
        } else {
            fail!("No public key");
        };
        if key.len() != 32 {
            fail!("Bad public key");
        } 
        let key = &key[..32];
        let pub_key = from_slice!(key, 32);
        Ok(
            Self {
                id: Self::calc_id(src.type_id, &pub_key), 
                keys: [Some(pub_key), None, None],
                type_id: src.type_id
            }
        )
    }

    /// Create from TL object with public key 
    pub fn from_tl_public_key(src: &ton::PublicKey) -> Result<Self> {
        if let ton::PublicKey::Pub_Ed25519(key) = src {
            Ok(Self::from_type_and_public_key(Self::KEY_ED25519, &key.key.0))
        } else {
            fail!("Unsupported public key type {:?}", src)
        }
    }

    /// Create from TL serialized public key 
    pub fn from_tl_serialized_public_key(src: &[u8]) -> Result<Self> {
        let pub_key = deserialize(src)?
            .downcast::<ton::PublicKey>()
            .map_err(|key| failure::format_err!("Unsupported PublicKey data {:?}", key))?;
        Self::from_tl_public_key(&pub_key)
    }

    /// Create from type and private key 
    pub fn from_type_and_private_key(
        type_id: i32, 
        pvt_key: &[u8; 32]
    ) -> Result<(KeyOptionJson, Self)> {
        if type_id != Self::KEY_ED25519 {
            fail!("Import from private key is available for Ed25519 key only")
        }
        let sec_key = ed25519_dalek::SecretKey::from_bytes(pvt_key)?;
        let json = KeyOptionJson {
            type_id,
            pub_key: None,
            pvt_key: Some(base64::encode(pvt_key))
        };
        Ok((json, Self::from_ed25519_secret_key(sec_key)))
    }

    /// Create from type and public key 
    pub fn from_type_and_public_key(type_id: i32, pub_key: &[u8; 32]) -> Self {
        Self {
            id: Self::calc_id(type_id, pub_key), 
            keys: [Some(pub_key.clone()), None, None],
            type_id
        }
    }

    /// Generate 
    pub fn with_type_id(type_id: i32) -> Result<(KeyOptionJson, Self)> {
        if type_id != Self::KEY_ED25519 {
            fail!("Generate is available for Ed25519 key only")
        }
        let sec_key = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng());
        let json = KeyOptionJson {
            type_id,
            pub_key: None,
            pvt_key: Some(base64::encode(&sec_key.to_bytes()))
        };
        Ok((json, Self::from_ed25519_secret_key(sec_key)))
    }

    /// Get key id 
    pub fn id(&self) -> &Arc<KeyId> {
        &self.id
    }

    /// Get expansion of private key
    pub fn exp_key(&self) -> Result<&[u8; 32]> {
        if let Some(exp_key) = self.keys[2].as_ref() {
            Ok(exp_key)
        } else {
            fail!("No expansion key set for key {}", self.id())
        }
    }

    /// Get public key
    pub fn pub_key(&self) -> Result<&[u8; 32]> {
        if let Some(pub_key) = self.keys[0].as_ref() {
            Ok(pub_key)
        } else {
            fail!("No public key set for key {}", self.id())
        }
    }

    /// Get private key
    pub fn pvt_key(&self) -> Result<&[u8; 32]> {
        if let Some(pvt_key) = self.keys[1].as_ref() {
            Ok(pvt_key)
        } else {
            fail!("No private key set for key {}", self.id())
        }
    }

    /// Get type id 
    pub fn type_id(&self) -> i32 {
        self.type_id
    }

    /// Export into TL object with public key 
    pub fn into_tl_public_key(&self) -> Result<ton::PublicKey> {
        if self.type_id != Self::KEY_ED25519 {
            fail!("Export is supported only for Ed25519 keys")
        }
        let ret = Ed25519 { 
            key: ton::int256(self.pub_key()?.clone()) 
        }.into_boxed();
        Ok(ret)
    }

    /// Generate signature 
    pub fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        if self.type_id != Self::KEY_ED25519 {
            fail!("Sign is available for Ed25519 key only")
        }
        let mut exp_key = self.pvt_key()?.to_vec();
        exp_key.extend_from_slice(self.exp_key()?);
        let exp_key = ed25519_dalek::ExpandedSecretKey::from_bytes(&exp_key)?;
        let pub_key = if let Ok(key) = self.pub_key() {
            ed25519_dalek::PublicKey::from_bytes(key)?
        } else {
            ed25519_dalek::PublicKey::from(&exp_key)
        };
        Ok(exp_key.sign(data, &pub_key).to_bytes())
    }

    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        if self.type_id != Self::KEY_ED25519 {
            fail!("Verify is available for Ed25519 key only")
        }
        let pub_key = ed25519_dalek::PublicKey::from_bytes(self.pub_key()?)?;
        pub_key.verify(data, &ed25519::Signature::from_bytes(signature)?)?;
        Ok(())
    }

    /// Calculate key ID
    fn calc_id(type_id: i32, pub_key: &[u8; 32]) -> Arc<KeyId> {
        let mut sha = sha2::Sha256::new();
        sha.input(&type_id.to_le_bytes());
        sha.input(pub_key);    
        let buf = sha.result_reset();      
        let src = buf.as_slice();         
        KeyId::from_data(from_slice!(src, 32))
    }

}

/// ADNL/RLDP Query 
#[derive(Debug)]
pub enum Query {
    Received(Vec<u8>),
    Sent(Arc<tokio::sync::Barrier>),
    Timeout
}

impl Query {

    /// Construct new query
    pub fn new() -> (Arc<tokio::sync::Barrier>, Self) {
        let ping = Arc::new(tokio::sync::Barrier::new(2));
        let pong = ping.clone();
        (ping, Query::Sent(pong))
    }

    /// Build query
    pub fn build(prefix: Option<&[u8]>, query: &TLObject) -> Result<(QueryId, AdnlMessage)> {
        let query_id: QueryId = rand::thread_rng().gen();
        let query = if let Some(prefix) = prefix {
            let mut prefix = prefix.to_vec();
            serialize_append(&mut prefix, query)?;
            prefix
        } else {
            serialize(query)?
        };
        let message = AdnlQueryMessage {
            query_id: ton::int256(query_id.clone()),
            query: ton::bytes(query)
        }.into_boxed();
        Ok((query_id, message))
    }

    /// Parse answer
    pub fn parse<Q, A>(answer: TLObject, query: &Q) -> Result<A> 
    where 
        A: BoxedSerialize + Send + Sync + serde::Serialize + 'static,
        Q: Debug
    {
        match answer.downcast::<A>() {
            Ok(answer) => Ok(answer), 
            Err(answer) => fail!("Unsupported response to {:?}: {:?}", query, answer)
        }
    }
    
    /// Process ADNL query
    pub async fn process_adnl(
        subscribers: &Vec<Arc<dyn Subscriber>>,
        query: &AdnlQueryMessage,
        peers: &AdnlPeers                                                                    
    ) -> Result<(bool, Option<AdnlMessage>)> {
        if let (true, answer) = Self::process(subscribers, &query.query[..], peers).await? {
            Self::answer(
                answer,
                |answer| AdnlAnswerMessage {
                    query_id: query.query_id.clone(),  
                    answer: ton::bytes(answer)
                }.into_boxed()
            )
        } else {
            Ok((false, None))
        }
    }

    /// Process custom message
    pub async fn process_custom(
        subscribers: &Vec<Arc<dyn Subscriber>>,
        custom: &AdnlCustomMessage,
        peers: &AdnlPeers
    ) -> Result<bool> {
        for subscriber in subscribers.iter() {
            if subscriber.try_consume_custom(&custom.data, peers).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Process RLDP query
    pub async fn process_rldp(
        subscribers: &Vec<Arc<dyn Subscriber>>,
        query: &RldpQuery,                                                               
        peers: &AdnlPeers     
    ) -> Result<(bool, Option<RldpAnswer>)> {
        if let (true, answer) = Self::process(subscribers, &query.data[..], peers).await? {
            Self::answer(
                answer, 
                |answer| RldpAnswer {
                    query_id: query.query_id.clone(),  
                    data: ton::bytes(answer)
                }
            )
        } else {
            Ok((false, None))
        }
    }

    fn answer<A>(
        answer: Option<Answer>,
        convert: impl Fn(Vec<u8>) -> A
    ) -> Result<(bool, Option<A>)> {
        let answer = match answer {
            Some(Answer::Object(x)) => Some(serialize(&x)?),
            Some(Answer::Raw(x)) => Some(x),
            None => None
        };
        Ok((true, answer.map(convert)))
    }

    async fn process(
        subscribers: &Vec<Arc<dyn Subscriber>>,
        query: &[u8],
        peers: &AdnlPeers
    ) -> Result<(bool, Option<Answer>)> {
        let mut queries = deserialize_bundle(query)?;
        if queries.len() == 1 {
            let mut query = queries.remove(0);
            for subscriber in subscribers.iter() {
                query = match subscriber.try_consume_query(query, peers).await? {
                    QueryResult::Consumed(answer) => return Ok((true, answer)),
                    QueryResult::Rejected(query) => query,
                    QueryResult::RejectedBundle(_) => unreachable!()
                };
            }
        } else {
            for subscriber in subscribers.iter() {
                queries = match subscriber.try_consume_query_bundle(queries, peers).await? {
                    QueryResult::Consumed(answer) => return Ok((true, answer)),
                    QueryResult::Rejected(_) => unreachable!(),
                    QueryResult::RejectedBundle(queries) => queries
                };
            }
        };
        Ok((false, None))
    }

}

/// ADNL query cache
//pub type QueryCache = HashMap<QueryId, Query>;
pub type QueryCache = lockfree::map::Map<QueryId, Query>;

/// ADNL query ID
pub type QueryId = [u8; 32];

/// ADNL/RLDP query consumption result
pub enum QueryResult {
    /// Consumed with optional answer
    Consumed(Option<Answer>), 
    /// Rejected 
    Rejected(TLObject),         
    /// Rejected bundle
    RejectedBundle(Vec<TLObject>)            
}

impl QueryResult {                        

    /// Consume plain helper
    pub fn consume<A: IntoBoxed>(answer: A) -> Result<Self> 
        where <A as IntoBoxed>::Boxed: Send + Sync + serde::Serialize + 'static 
    {
        Ok(QueryResult::Consumed(Some(Answer::Object(TLObject::new(answer.into_boxed())))))
    }

    /// Consume boxed helper
    pub fn consume_boxed<A>(answer: A) -> Result<Self> 
        where A: BoxedSerialize + Send + Sync + serde::Serialize + 'static
    {
        Ok(QueryResult::Consumed(Some(Answer::Object(TLObject::new(answer)))))
    }

}

/// ADNL subscriber
#[async_trait::async_trait]
pub trait Subscriber: Send + Sync {
    /// Try consume custom data: data -> consumed yes/no
    async fn try_consume_custom(&self, _data: &[u8], _peers: &AdnlPeers) -> Result<bool> {
        Ok(false)
    }
    /// Try consume query: object -> result
    async fn try_consume_query(
        &self, 
        object: TLObject, 
        _peers: &AdnlPeers
    ) -> Result<QueryResult> {
        Ok(QueryResult::Rejected(object))
    }
    /// Try consume query bundle: objects -> result
    async fn try_consume_query_bundle(
        &self, 
        objects: Vec<TLObject>,
        _peers: &AdnlPeers
    ) -> Result<QueryResult> {
        Ok(QueryResult::RejectedBundle(objects))
    }
}

/// Network timeouts
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Timeouts {
    read:  Duration,
    write: Duration
}

impl Timeouts {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
    /// Read timeout
    pub fn read(&self) -> Option<Duration> {
        Some(self.read)
    }
    /// Write timeout
    pub fn write(&self) -> Option<Duration> {
        Some(self.write)
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            read:  Self::DEFAULT_TIMEOUT,
            write: Self::DEFAULT_TIMEOUT
        }
    }
}

/// Data structure version
pub struct Version;

impl Version {
    pub fn get() -> i32 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i32
    }
}

/// Data structure update timestamp
pub struct UpdatedAt {
    started: Instant,
    updated: AtomicU64
}

impl UpdatedAt {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            updated: AtomicU64::new(0)
        }
    }
    pub fn refresh(&self) {
        self.updated.store(self.started.elapsed().as_secs(), Ordering::Relaxed)
    }
    pub fn is_expired(&self, timeout: u64) -> bool {
        self.started.elapsed().as_secs() - self.updated.load(Ordering::Relaxed) >= timeout
    }
}

pub struct Wait<T> {
    count: AtomicUsize,  
    queue_sender: tokio::sync::mpsc::UnboundedSender<Option<T>>
}

impl <T> Wait<T> {

    pub fn new() -> (Arc<Self>, tokio::sync::mpsc::UnboundedReceiver<Option<T>>) {
        let (queue_sender, queue_reader) = tokio::sync::mpsc::unbounded_channel(); 
        let ret = Self {
            count: AtomicUsize::new(0), 
            queue_sender
        };
        (Arc::new(ret), queue_reader)
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn request(&self) -> usize {
        self.count.fetch_add(1, Ordering::Relaxed)
    }

    pub fn respond(&self, val: Option<T>) {
        match self.queue_sender.send(val) {
            Ok(()) => (),
            Err(tokio::sync::mpsc::error::SendError(_)) => ()
        }
    }

    pub async fn wait(
        &self, 
        queue_reader: &mut tokio::sync::mpsc::UnboundedReceiver<Option<T>>,
        only_one: bool
    ) -> Option<Option<T>> {
        let mut empty = self.count.load(Ordering::Relaxed) == 0;
        let mut ret = None;
        if !empty {
            ret = queue_reader.recv().await;
            match ret {   
                Some(ref item) => {
                    self.count.fetch_sub(1, Ordering::Relaxed);
                    if item.is_some() && only_one {
                        empty = true
                    }
                },
                None => empty = true
            }
        }
        if empty { 
            // Graceful close
            queue_reader.close();
            while let Some(_) = queue_reader.recv().await {
            }
        }
        ret
    }

}

/// Add object to map
pub fn add_object_to_map<K: Hash + Ord, V>(
    to: &lockfree::map::Map<K, V>, 
    key: K, 
    mut factory: impl FnMut() -> Result<V>
) -> Result<bool> {
    add_object_to_map_with_update(
        to,
        key,
        |found| if found.is_some() {
            Ok(None)
        } else {
            Ok(Some(factory()?))
        }
    )
}

/// Add or update object in map
pub fn add_object_to_map_with_update<K: Hash + Ord, V>(
    to: &lockfree::map::Map<K, V>, 
    key: K, 
    mut factory: impl FnMut(Option<&V>) -> Result<Option<V>>
) -> Result<bool> {
    let mut error = None; 
    let insertion = to.insert_with(
        key,
        |_, inserted, found| {
            let found = if let Some((_, found)) = found {
                Some(found)
            } else if inserted.is_some() {
                return lockfree::map::Preview::Keep
            } else {
                None
            };
            match factory(found) {
                Err(err) => error = Some(err),
                Ok(Some(value)) => return lockfree::map::Preview::New(value),
                _ => ()
            }
            lockfree::map::Preview::Discard
        }
    );
    match insertion {
        lockfree::map::Insertion::Created => Ok(true),
        lockfree::map::Insertion::Failed(_) => if let Some(error) = error {
            Err(error)
        } else {
            Ok(false)
        },
        lockfree::map::Insertion::Updated(_) => Ok(true)
    }
}

/// Deserialize TL object from bytes
pub fn deserialize(bytes: &[u8]) -> Result<TLObject> {
    let mut reader = bytes;
    Deserializer::new(&mut reader).read_boxed::<TLObject>()
}

/// Deserialize bundle of TL objects from bytes
pub fn deserialize_bundle(bytes: &[u8]) -> Result<Vec<TLObject>> {
    let mut reader = bytes;
    let mut de = Deserializer::new(&mut reader);
    let mut ret = Vec::new();
    loop {
        match de.read_boxed::<TLObject>() {
            Ok(object) => ret.push(object),
            Err(_) => if ret.is_empty() {
                fail!("Deserialization error")
            } else {
                break
            }
        }
    }
    Ok(ret)
}

/// Get 256 bits as byte array out of ton::int256 
pub fn get256(src: &ton::int256) -> &[u8; 32] {
    let ton::int256(ret) = src;
    ret
}

/// Calculate hash of TL object, non-boxed option
pub fn hash<T: IntoBoxed>(object: T) -> Result<[u8; 32]> {
    hash_boxed(&object.into_boxed())
}

/// Calculate hash of TL object, boxed option
pub fn hash_boxed<T: BoxedSerialize>(object: &T) -> Result<[u8; 32]> {
    let data = serialize(object)?;
    let buf = sha2::Sha256::digest(&data[..]);
    let hash = buf.as_slice();
    Ok(from_slice!(hash, 32))
}

/// Serialize TL object into bytes
pub fn serialize<T: BoxedSerialize>(object: &T) -> Result<Vec<u8>> {
    let mut ret = Vec::new();
    Serializer::new(&mut ret).write_boxed(object)?;
    Ok(ret)
}

/// Serialize TL object into bytes with appending
pub fn serialize_append<T: BoxedSerialize>(buf: &mut Vec<u8>, object: &T) -> Result<()> {
    Serializer::new(buf).write_boxed(object)?;
    Ok(())
}

/// Serialize TL object into bytes in-place
pub fn serialize_inplace<T: BoxedSerialize>(buf: &mut Vec<u8>, object: &T) -> Result<()> {
    buf.truncate(0); 
    serialize_append(buf, object)
}
