use crate::{
    common::{
        AdnlHandshake, AdnlStream, AdnlStreamCrypto, deserialize, get256, 
        KeyOption, KeyOptionJson, Query, serialize, TaggedTlObject, Timeouts
    }
};
use rand::Rng;
use std::{convert::TryInto, net::SocketAddr, time::{Duration, SystemTime}};
use ton_api::ton::{
    TLObject, adnl::{Message as AdnlMessage, Pong as AdnlPongBoxed},
    rpc::adnl::Ping as AdnlPing
};
#[cfg(feature = "telemetry")]
use ton_api::{BoxedSerialize, ConstructorNumber};
use ton_types::{error, fail, Result};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AdnlClientConfigJson {
    client_key: Option<KeyOptionJson>,
    server_address: String,
    server_key: KeyOptionJson,
    timeouts: Option<Timeouts>
}

impl AdnlClientConfigJson {
    pub fn with_params(server: &str, server_key: KeyOptionJson, timeouts: Option<Timeouts>) -> Self {
        AdnlClientConfigJson {
            client_key: None,
            server_address: server.to_string(),
            server_key: server_key,
            timeouts: timeouts
        }
    }
}

/// ADNL client configuration
pub struct AdnlClientConfig {
    client_key: Option<KeyOption>,
    server_address: SocketAddr,
    server_key: KeyOption,
    timeouts: Timeouts
}

impl AdnlClientConfig {

    /// Costructs new configuration from JSON string
    pub fn from_json(json: &str) -> Result<(Option<AdnlClientConfigJson>, Self)> {
        let json_config: AdnlClientConfigJson = serde_json::from_str(json)?;
        Self::from_json_config(json_config)
    }
    
    /// Costructs new configuration from JSON data
    pub fn from_json_config(
        json_config: AdnlClientConfigJson
    ) -> Result<(Option<AdnlClientConfigJson>, Self)> {
        let server_key = KeyOption::from_public_key(&json_config.server_key)?;
        let mut result_config = None;
        let client_key = if let Some(key) = &json_config.client_key {
            Some(KeyOption::from_private_key(key)?)
        } else {
            let (json, key) = KeyOption::with_type_id(KeyOption::KEY_ED25519)?;
            result_config = Some(
                AdnlClientConfigJson {
                    client_key: Some(json),
                    server_address: json_config.server_address.clone(),
                    server_key: json_config.server_key,
                    timeouts: json_config.timeouts.clone()
                }
            );
            Some(key)
        };
        let ret = AdnlClientConfig {
            client_key,
            server_address: json_config.server_address.parse()?,
            server_key,
            timeouts: if let Some(timeouts) = json_config.timeouts {
                timeouts
            } else {
                Timeouts::default()
            }
        };
        Ok((result_config, ret))
    }

    /// Get timeouts
    pub fn timeouts(&self) -> &Timeouts {
        &self.timeouts
    }

}

/// ADNL client
pub struct AdnlClient{
    crypto: AdnlStreamCrypto,
    stream: AdnlStream
}

impl AdnlClient {

    /// Connect to server
    pub async fn connect(config: &AdnlClientConfig) -> Result<Self> {

        let socket = socket2::Socket::new(
            socket2::Domain::ipv4(), 
            socket2::Type::stream(), 
            Some(socket2::Protocol::tcp())
        )?;
        socket.set_reuse_address(true)?;
        socket.set_linger(Some(Duration::from_secs(0)))?;
        //socket.bind(&"0.0.0.0:0".parse::<SocketAddr>()?.into())?;
        socket.connect_timeout(
            &config.server_address.into(), 
            config.timeouts.write()
        )?;

        let mut stream = AdnlStream::from_stream_with_timeouts(
            tokio::net::TcpStream::from_std(socket.into_tcp_stream())?,
            config.timeouts()
        );
        Ok(
            Self { 
                crypto: Self::send_init_packet(&mut stream, config).await?, 
                stream
            }
        )

    }

    /// Ping server
    pub async fn ping(&mut self) -> Result<u64> {
        let now = SystemTime::now();
        let value = rand::thread_rng().gen();
        let query = TLObject::new(
            AdnlPing { 
                value 
            }
        );
        #[cfg(feature = "telemetry")]
        let (ConstructorNumber(tag), _) = query.serialize_boxed();
        let query = TaggedTlObject {
            object: query,
            #[cfg(feature = "telemetry")]
            tag
        };
        let answer: AdnlPongBoxed = Query::parse(self.query(&query).await?, &query.object)?;
        if answer.value() != &value {
            fail!("Bad reply to ADNL ping")
        }
        Ok(now.elapsed()?.as_secs())
    }

    /// Shutdown client
    pub async fn shutdown(mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Query server
    pub async fn query(&mut self, query: &TaggedTlObject) -> Result<TLObject> {
        let (query_id, msg) = Query::build(None, query)?;        
        let mut buf = serialize(&msg.object)?;
        self.crypto.send(&mut self.stream, &mut buf).await?;
        loop {
            self.crypto.receive(&mut buf, &mut self.stream).await?;
            if !buf.is_empty() {
                break;
            }
        }
        let answer = deserialize(&buf[..])?
            .downcast::<AdnlMessage>()
            .map_err(|answer| error!("Unsupported ADNL message {:?}", answer))?;
        match answer {
            AdnlMessage::Adnl_Message_Answer(answer) => if &query_id == get256(&answer.query_id) {
                deserialize(&answer.answer)
            } else {
                fail!("Query ID mismatch {:?} vs {:?}", query.object, answer)
            },
            _ => fail!("Unexpected answer to query {:?}: {:?}", query.object, answer)
        } 
    }

    async fn send_init_packet(
        stream: &mut AdnlStream, 
        config: &AdnlClientConfig
    ) -> Result<AdnlStreamCrypto> {
        let mut rng = rand::thread_rng();
        let mut buf: Vec<u8> = (0..160).map(|_| rng.gen()).collect();
        let nonce = buf.as_slice().try_into()?;
        let ret = AdnlStreamCrypto::with_nonce_as_client(nonce);
        if let Some(client_key) = &config.client_key {
            AdnlHandshake::build_packet(&mut buf, client_key, &config.server_key)?
        } else {
            AdnlHandshake::build_packet(
                &mut buf, 
                &KeyOption::from_ed25519_secret_key(ed25519_dalek::SecretKey::generate(&mut rng))?,
                &config.server_key
            )?
        }
        stream.write(&mut buf).await?;
        Ok(ret)
    }

}
