use crate::{
    dump, 
    common::{
        AdnlHandshake, AdnlStream, AdnlStreamCrypto, deserialize, KeyId, 
        KeyOption, KeyOptionJson, Query, serialize_inplace, Subscriber, TARGET, Timeouts
    }
};
use std::{
    net::SocketAddr, sync::Arc
};
use stream_cancel::StreamExt;
use futures::prelude::*;
use ton_api::ton::adnl::Message as AdnlMessage;
use ton_types::{fail, Result};

/// ADNL server configuration
pub struct AdnlServerConfig {
    address: SocketAddr,
    keys: Arc<lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>>,
    timeouts: Timeouts
}

#[derive(serde::Deserialize)]
struct AdnlServerConfigJson {
    address: String,
    keys: Vec<KeyOptionJson>,
    timeouts: Option<Timeouts>
}

impl AdnlServerConfig {

    /// Costructs from JSON data
    pub fn from_json(json: &str) -> Result<Self> {
        let json_config: AdnlServerConfigJson = serde_json::from_str(json)?;
        let keys = lockfree::map::Map::new();
        for key in json_config.keys.iter() {
            let key = KeyOption::from_private_key(key)?;
            let id = key.id().clone();
            if keys.insert(id.clone(), Arc::new(key)).is_some() {
                fail!("Duplicated key {} in server configuration", id)
            }
        }
        let ret = AdnlServerConfig {
            address: json_config.address.parse()?,
            keys: Arc::new(keys),
            timeouts: if let Some(timeouts) = json_config.timeouts {
                timeouts
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
        let keys = config.keys.clone();
        tokio::spawn(
            async move {
                if let Err(e) = AdnlServerThread::run(stream, &keys, subscribers).await {
                    log::warn!(target: TARGET, "ERROR --> {}", e);
                    return;
                }
                unreachable!();
            }
        );
    }

    async fn run(
        mut stream: AdnlStream,
        keys: &Arc<lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>>,
        subscribers: Arc<Vec<Arc<dyn Subscriber>>>
    ) -> Result<()> {
        let mut buf = Vec::with_capacity(256);
        stream.read(&mut buf, 256).await?;
        let mut crypto = Self::parse_init_packet(&keys, &mut buf)?;
        buf.truncate(0);
        crypto.send(&mut stream, &mut buf).await?;
        loop {
            crypto.receive(&mut buf, &mut stream).await?;
            let msg = deserialize(&buf[..])?
                .downcast::<AdnlMessage>()
                .map_err(|msg| failure::format_err!("Unsupported ADNL message {:?}", msg))?;
            let (consumed, reply) = match &msg {
                AdnlMessage::Adnl_Message_Custom(custom) => 
                    (Query::process_custom(&subscribers, &custom)?, None),
                AdnlMessage::Adnl_Message_Query(query) => 
                    Query::process(&subscribers, &query)?,
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
        keys: &lockfree::map::Map<Arc<KeyId>, Arc<KeyOption>>,
        buf: &mut Vec<u8>
    ) -> Result<AdnlStreamCrypto> {
        AdnlHandshake::parse_packet(&keys, buf, Some(160))?;
        dump!(trace, TARGET, "Nonce", &buf[..160]);
        let ret = AdnlStreamCrypto::with_nonce_as_server(
            arrayref::array_mut_ref!(buf, 0, 160)
        );
        buf.drain(0..160);
        return Ok(ret);
    }

}

/// ADNL server 
pub struct AdnlServer(stream_cancel::Trigger);

impl AdnlServer {

    /// Listen to connections
    pub async fn listen(
        config: AdnlServerConfig, 
        subscribers: Vec<Arc<dyn Subscriber>>
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
        let subscribers = Arc::new(subscribers);
        let mut listener = tokio::net::TcpListener::bind(config.address).await?;
        tokio::spawn(
            async move {
                let mut incoming = listener.incoming().take_until(tripwire);
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
