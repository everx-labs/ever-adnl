use crate::{
    dump, 
    common::{
        AdnlHandshake, AdnlStream, AdnlStreamCrypto, deserialize, get256, 
        KeyOption, KeyOptionJson, Query, serialize, TARGET, Timeouts
    }
};
use rand::Rng;
use std::{net::SocketAddr, time::Duration};
use ton_api::{
    IntoBoxed, 
    ton::{
        self, TLObject,  
        adnl::{
            Message as AdnlMessage, message::message::Custom as AdnlCustomMessage, 
        }
    }
};
use ton_types::{fail, Result};

/// ADNL client configuration
pub struct AdnlClientConfig {
    server_address: SocketAddr,
    server_key: KeyOption,
    timeouts: Timeouts
}

#[derive(serde::Deserialize)]
struct AdnlClientConfigJson {
    server_address: String,
    server_key: KeyOptionJson,
    timeouts: Option<Timeouts>
}

impl AdnlClientConfig {

    /// Costructs new configuration from JSON data
    pub fn from_json(json: &str) -> Result<Self> {
        let json_config: AdnlClientConfigJson = serde_json::from_str(json)?;
        let ret = AdnlClientConfig {
            server_address: json_config.server_address.parse()?,
            server_key: KeyOption::from_public_key(&json_config.server_key)?,
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
            config.timeouts.write().unwrap()
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

    /// Shutdown client
    pub async fn shutdown(mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Custom message to server
    pub async fn send_custom(&mut self, data: &[u8]) -> Result<()> {
        let msg = AdnlCustomMessage {
            data: ton::bytes(data.to_vec())
        }.into_boxed();
        self.crypto.send(&mut self.stream, &mut serialize(&msg)?).await?;
        Ok(())
    }

    /// Query server
    pub async fn query(&mut self, query: &TLObject) -> Result<TLObject> {
        let (query_id, msg) = Query::build(None, query)?;        
        let mut buf = serialize(&msg)?;
        self.crypto.send(&mut self.stream, &mut buf).await?;
        loop {
            self.crypto.receive(&mut buf, &mut self.stream).await?;
            if !buf.is_empty() {
                break;
            }
        }
        let answer = deserialize(&buf[..])?
            .downcast::<AdnlMessage>()
            .map_err(|answer| failure::format_err!("Unsupported ADNL message {:?}", answer))?;
        match answer {
            AdnlMessage::Adnl_Message_Answer(answer) => if &query_id == get256(&answer.query_id) {
                deserialize(&answer.answer)
            } else {
                fail!("Query ID mismatch {:?} vs {:?}", query, answer)
            },
            _ => fail!("Unexpected answer to query {:?}: {:?}", query, answer)
        } 
    }

    async fn send_init_packet(
        stream: &mut AdnlStream, 
        config: &AdnlClientConfig
    ) -> Result<AdnlStreamCrypto> {

        let mut rng = rand::thread_rng();
        let client_key = KeyOption::from_ed25519_secret_key(
            ed25519_dalek::SecretKey::generate(&mut rng)
        );

        let mut buf: Vec<u8> = (0..160).map(|_| rng.gen()).collect();
        let nonce = arrayref::array_ref!(buf, 0, 160);
        dump!(trace, TARGET, "Nonce", nonce);
        let ret = AdnlStreamCrypto::with_nonce_as_client(nonce);
        AdnlHandshake::build_packet(&mut buf, &client_key, &config.server_key)?;
        stream.write(&mut buf).await?;
        Ok(ret)

    }

}