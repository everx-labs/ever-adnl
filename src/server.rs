use crate::{
    dump, from_slice,
    common::{
        AdnlHandshake, AdnlPeers, AdnlPingSubscriber, AdnlStream, AdnlStreamCrypto, deserialize, 
        KeyId, KeyOption, KeyOptionJson, Query, serialize_inplace, Subscriber, TARGET, Timeouts
    }
};
use std::{
    net::SocketAddr, sync::Arc
};
use stream_cancel::StreamExt;
use futures::prelude::*;
use ton_api::ton::adnl::Message as AdnlMessage;
use ton_types::{error, fail, Result};

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum AdnlServerClients {
    Any,
    List(Vec<KeyOptionJson>)
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AdnlServerConfigJson {
    address: String,
    clients: AdnlServerClients,
    server_key: KeyOptionJson,
    timeouts: Option<Timeouts>
}

impl AdnlServerConfigJson {
    pub fn with_params(
        address: String,
        server_key: KeyOptionJson,
        client_keys: Vec<KeyOptionJson>,
        timeouts: Option<Timeouts>
    )-> Self {
        AdnlServerConfigJson {
            address: address,
            clients: AdnlServerClients::List(client_keys),
            server_key: server_key,
            timeouts: timeouts
        }
    }
}

/// ADNL server configuration
pub struct AdnlServerConfig {
    address: SocketAddr,
    clients: Arc<Option<lockfree::map::Map<[u8; 32], u8>>>,
    server_key: Arc<lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>>,
    timeouts: Timeouts
}

impl AdnlServerConfig {

    /// Costructs from JSON data
    pub fn from_json(json: &str) -> Result<Self> {
        let json_config: AdnlServerConfigJson = serde_json::from_str(json)?;
        Self::from_json_config(&json_config)
    }

    /// Construct from JSON config structure
    pub fn from_json_config(json_config: &AdnlServerConfigJson) -> Result<Self> {
        let key = KeyOption::from_private_key(&json_config.server_key)?;
        let server_key = lockfree::map::Map::new();
        server_key.insert(key.id().clone(), Arc::new(key));
        let clients = match &json_config.clients {
            AdnlServerClients::Any => None,
            AdnlServerClients::List(list) => {
                let clients = lockfree::map::Map::new();
                for key in list.iter() {
                    let key = KeyOption::from_public_key(key)?;
                    let key = key.pub_key()?;
                    if clients.insert(key.clone(), 0).is_some() {
                        fail!("Duplicated client key {} in server config", base64::encode(key))
                    }
                }
                Some(clients)
            }
        };
        let ret = AdnlServerConfig {
            address: json_config.address.parse()?,
            clients: Arc::new(clients),
            server_key: Arc::new(server_key),
            timeouts: if let Some(timeouts) = &json_config.timeouts {
                timeouts.clone()
            } else {
                Timeouts::default()
            }
        };
        Ok(ret)
    }

    /// Get timeouts
    pub fn timeouts(&self) -> &Timeouts {
        &self.timeouts
    }

}

/// ADNL server thread (one connection)
struct AdnlServerThread(Arc<Vec<Arc<dyn Subscriber>>>);

impl AdnlServerThread {

    fn spawn(
        stream: tokio::net::TcpStream,
        config: &AdnlServerConfig,
        subscribers: Arc<Vec<Arc<dyn Subscriber>>>
    ) {
        let stream = AdnlStream::from_stream_with_timeouts(stream, config.timeouts());
        let clients = config.clients.clone();
        let key = config.server_key.clone();
        tokio::spawn(
            async move {
                if let Err(e) = AdnlServerThread::run(stream, key, clients, subscribers).await {
                    log::warn!(target: TARGET, "ERROR --> {}", e);
                    return;
                }
                unreachable!();
            }
        );
    }

    async fn run(
        mut stream: AdnlStream,
        key: Arc<lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>>,
        clients: Arc<Option<lockfree::map::Map<[u8; 32], u8>>>,
        subscribers: Arc<Vec<Arc<dyn Subscriber>>>
    ) -> Result<()> {
        let mut buf = Vec::with_capacity(256);
        stream.read(&mut buf, 256).await?;
        if let Some(clients) = clients.as_ref() {
            // Check known client if any 
            if buf.len() < 64 {
                fail!("ADNL init message is too short ({})", buf.len())
            }
            if !clients.iter().any(|client| &buf[32..64] == client.key()) {
                fail!("Message from unknown client {}", base64::encode(&buf[32..64]))
            }
        }
        let (mut crypto, peers) = Self::parse_init_packet(&key, &mut buf)?;
        buf.truncate(0);
        crypto.send(&mut stream, &mut buf).await?;
        loop {
            crypto.receive(&mut buf, &mut stream).await?;
            let msg = deserialize(&buf[..])?
                .downcast::<AdnlMessage>()
                .map_err(|msg| failure::format_err!("Unsupported ADNL message {:?}", msg))?;
            let (consumed, reply) = match &msg {
                AdnlMessage::Adnl_Message_Query(query) => 
                    Query::process_adnl(&subscribers, &query, &peers).await?,
                _ => (false, None)                
            };
            if consumed {
                if let Some(msg) = reply {
                    serialize_inplace(&mut buf, &msg)?;
                    crypto.send(&mut stream, &mut buf).await?;
                }                
            } else {
                fail!("Unexpected ADNL message {:?}", msg);
            }
        }
    }

    fn parse_init_packet(
        key: &lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>,
        buf: &mut Vec<u8>
    ) -> Result<(AdnlStreamCrypto, AdnlPeers)> {
        let other_key = &buf[32..64];
        let other_key = from_slice!(other_key, 32);
        let local_key = AdnlHandshake::parse_packet(key, buf, Some(160))?.ok_or_else(
            || error!("Unknown ADNL server key, cannot decrypt")
        )?;
        let other_key = KeyOption::from_type_and_public_key(
            KeyOption::KEY_ED25519, 
            &other_key
        ).id().clone();
        dump!(trace, TARGET, "Nonce", &buf[..160]);
        let ret = AdnlStreamCrypto::with_nonce_as_server(
            arrayref::array_mut_ref!(buf, 0, 160)
        );
        buf.drain(0..160);
        Ok((ret, AdnlPeers::with_keys(local_key, other_key)))
    }

}

/// ADNL server 
pub struct AdnlServer(stream_cancel::Trigger);

impl AdnlServer {

    /// Listen to connections
    pub async fn listen(
        config: AdnlServerConfig, 
        mut subscribers: Vec<Arc<dyn Subscriber>>
    ) -> Result<Self> {
        let (trigger, tripwire) = stream_cancel::Tripwire::new();
/*
        let socket = socket2::Socket::new(
            socket2::Domain::ipv4(), 
            socket2::Type::stream(), 
            Some(socket2::Protocol::tcp())
        )?;
        socket.set_reuse_address(true)?;
        socket.set_linger(Some(Duration::from_secs(0)))?;    
        let addr: socket2::SockAddr = config.address.clone().into();
        socket.bind(&addr)?;
        let mut listener = tokio::net::TcpListener::from_std(socket.into_tcp_listener())?;
*/
        subscribers.push(Arc::new(AdnlPingSubscriber));
        let subscribers = Arc::new(subscribers);
        let mut listener = tokio::net::TcpListener::bind(config.address).await?;
        tokio::spawn(
            async move {
                let mut incoming = listener.incoming().take_until_if(tripwire);
                loop {
                    match incoming.next().await {
                        Some(Err(e)) =>
                            log::warn!(target: TARGET, "Error in listener {}", e.to_string()),
                        Some(Ok(stream)) => {
                            AdnlServerThread::spawn(stream, &config, subscribers.clone());
                            continue;
                        },
                        _ => ()
                    }
                    break;
                }
            }
        );
        Ok(Self(trigger))
    }

    /// Shutdown client
    pub fn shutdown(self) {
        drop(self.0);
    }

}
