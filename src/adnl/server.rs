/*
* Copyright (C) 2019-2023 EverX. All Rights Reserved.
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
    dump,
    common::{
        AdnlHandshake, AdnlPeers, AdnlPingSubscriber, AdnlStream, AdnlStreamCrypto, 
        Query, Subscriber, TARGET, Timeouts
    }
};
use std::{convert::TryInto, net::SocketAddr, sync::Arc, time::Duration};
use stream_cancel::StreamExt;
use futures::prelude::*;
use ton_api::{deserialize_boxed, serialize_boxed_inplace, {ton::adnl::Message as AdnlMessage}};
use ton_types::{
    error, fail, base64_encode, Ed25519KeyOption, KeyId, KeyOption, KeyOptionJson, Result
};

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
            address,
            clients: AdnlServerClients::List(client_keys),
            server_key,
            timeouts
        }
    }
}

/// ADNL server configuration
pub struct AdnlServerConfig {
    address: SocketAddr,
    clients: Arc<Option<lockfree::map::Map<[u8; 32], u8>>>,
    server_key: Arc<lockfree::map::Map<Arc<KeyId>, Arc<dyn KeyOption>>>,
    server_id: Arc<KeyId>,
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
        let key = Ed25519KeyOption::from_private_key_json(&json_config.server_key)?;
        let server_key = lockfree::map::Map::new();
        let server_id = key.id().clone();
        server_key.insert(key.id().clone(), key);
        let clients = match &json_config.clients {
            AdnlServerClients::Any => None,
            AdnlServerClients::List(list) => {
                let clients = lockfree::map::Map::new();
                for key in list.iter() {
                    let key = Ed25519KeyOption::from_public_key_json(key)?;
                    let key = key.pub_key()?;
                    if clients.insert(key.try_into()?, 0).is_some() {
                        fail!("Duplicated client key {} in server config", base64_encode(key))
                    }
                }
                Some(clients)
            }
        };
        let ret = AdnlServerConfig {
            address: json_config.address.parse()?,
            clients: Arc::new(clients),
            server_key: Arc::new(server_key),
            server_id,
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

    /// Get server ID
    pub fn server_id(&self) -> &[u8; 32] {
        self.server_id.data()
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
                    log::warn!(target: TARGET, "ADNL server ERROR --> {}", e);
                    return;
                }
                unreachable!();
            }
        );
    }

    async fn run(
        mut stream: AdnlStream,
        key: Arc<lockfree::map::Map<Arc<KeyId>, Arc<dyn KeyOption>>>,
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
                fail!("Message from unknown client {}", base64_encode(&buf[32..64]))
            }
        }
        let (mut crypto, peers) = Self::parse_init_packet(&key, &mut buf)?;
        buf.truncate(0);
        crypto.send(&mut stream, &mut buf).await?;
        loop {
            crypto.receive(&mut buf, &mut stream).await?;
            let msg = deserialize_boxed(&buf[..])?
                .downcast::<AdnlMessage>()
                .map_err(|msg| error!("Unsupported ADNL message {:?}", msg))?;
            let answer = match &msg {
                AdnlMessage::Adnl_Message_Query(query) => 
                    Query::process_adnl(&subscribers, query, &peers).await?,
                _ => None
            };
            if let Some(answer) = answer {
                let msg = match answer.try_finalize()? {
                    (Some(answer), _) => answer.wait().await?,
                    (None, msg) => msg
                };
                if let Some(msg) = msg {
                    serialize_boxed_inplace(&mut buf, &msg.object)?;
                    crypto.send(&mut stream, &mut buf).await?;
                }
            } else {
                fail!("Unexpected ADNL message {:?}", msg);
            }
        }
    }

    fn parse_init_packet(
        key: &lockfree::map::Map<Arc<KeyId>, Arc<dyn KeyOption>>,
        buf: &mut Vec<u8>
    ) -> Result<(AdnlStreamCrypto, AdnlPeers)> {
        let other_key = buf[32..64].try_into()?;
        let (local_key, version) = AdnlHandshake::parse_packet(key, buf, Some(160), false)?;
        let local_key = local_key.ok_or_else(
            || error!("Unknown ADNL server key, cannot decrypt")
        )?;
        if version.is_some() {
            fail!("Unsupported ADNL versioning {} in TCP connection")
        }
        let other_key = Ed25519KeyOption::from_public_key(&other_key).id().clone();
        dump!(trace, TARGET, "Nonce", &buf[..160]);
        let nonce: &mut [u8; 160] = buf.as_mut_slice().try_into()?;
        let ret = AdnlStreamCrypto::with_nonce_as_server(nonce);
        buf.drain(0..160);
        Ok((ret, AdnlPeers::with_keys(local_key, other_key)))
    }

}

/// ADNL server 
pub struct AdnlServer(stream_cancel::Trigger);

impl AdnlServer {

    const TIMEOUT_SHUTDOWN: u64 = 100; // Milliseconds

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
        let listener = tokio::net::TcpListener::bind(config.address).await?;
        tokio::spawn(
            async move {
                let mut incoming = tokio_stream::wrappers::TcpListenerStream::new(listener)
                    .take_until_if(tripwire);
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

    /// Shutdown server
    pub async fn shutdown(self) {
        drop(self.0);
        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_SHUTDOWN)).await;
    }

}
