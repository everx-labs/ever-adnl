/*
* Copyright (C) 2019-2023 EverX. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific EVERX DEV software governing permissions and
* limitations under the License.
*/

// TO REMOVE AFTER FULL REBRANDING
extern crate adnl as dht;
extern crate adnl as overlay;
extern crate adnl as rldp;
extern crate ton_api as ever_api;

use adnl::{common::Subscriber, node::{AdnlNode, IpAddress}};
use dht::{DhtNode, DhtIterator, DhtSearchPolicy, OverlayNodesSearchContext};
use ever_api::{
    IntoBoxed, 
    ton::{//ever::{
        adnl::addresslist::AddressList, dht::node::Node, pub_::publickey::Ed25519
    }
};
use ever_api::ton/*ever*/::overlay::node::Node as NodeOverlay;
use ever_block::{error, base64_decode, KeyId, UInt256};
use overlay::{OverlayNode, OverlayShortId};
use std::{io::{BufRead, BufReader}, sync::Arc};
use rldp::RldpNode;
                             
include!("../common/src/config.rs");
include!("../common/src/test.rs");

struct OtherNode {
    key: String,
    ip: String,
    signature: String,
    timestamp: Option<i32>
}

fn build_dht_node_info_with_timestamp(
    ip: &str, 
    key: &str, 
    signature: &str,
    timestamp: Option<i32>
) -> Result<Node> {
    let key = base64_decode(key)?;
    if key.len() != 32 {
        fail!("Bad public key length")
    }
    let key: [u8; 32] = key.as_slice().try_into()?;
    let addrs = vec![IpAddress::from_versioned_string(ip, None)?.into_udp().into_boxed()];
    let signature = base64_decode(signature)?;
    let node = Node {
        id: Ed25519 {
            key: UInt256::with_array(key)
        }.into_boxed(),
        addr_list: AddressList {
            addrs: addrs.into(),
            version: timestamp.unwrap_or(0),
            reinit_date: timestamp.unwrap_or(0),
            priority: 0,
            expire_at: 0
        },
        version: timestamp.unwrap_or(-1),
        signature: signature.into()
    };
    Ok(node)
}

fn extract_other_nodes(config: &str) -> Vec<OtherNode> {

    const MASK_READ_KEY: u16 = 0x0001;
    const MASK_READ_IP: u16 = 0x0002;
    const MASK_READ_PORT: u16 = 0x0004;

    let mut ret = Vec::new();
    let file = File::open(config).expect("Config file not found");
    let buf_reader = BufReader::new(file);
    
    let mut key: Option<String> = None;
    let mut ip: Option<String> = None;
    let mut mask = 0;
    let mut timestamp = None;

    for line in buf_reader.lines() {
        let line = line.unwrap();
        let line = line.trim();
        if line.strip_prefix("\"@type\": \"pub.ed25519\"").is_some() {
            mask |= MASK_READ_KEY;
            key = None;
            ip = None;
            continue;
        }
        if line.strip_prefix("\"@type\": \"adnl.address.udp\"").is_some() {
            mask |= MASK_READ_IP;                                 
            continue;
        }
        if let Some(line) = line.strip_prefix("\"version\": ") {
            if let Some(line) = line.strip_suffix(",") {
                match line.parse::<i32>().expect("Timestamp") {
                    0 | -1 => (),
                    version => timestamp = Some(version)
                }
            }
            continue;
        }
        if let Some(line) = line.strip_prefix("\"signature\": \"") {
            if let Some(signature) = line.strip_suffix("\"") {
                if let Some(key) = key.as_ref() {
                    if let Some(ip) = ip.as_ref() {
                        let node = OtherNode {
                            key: key.to_string(), 
                            ip: ip.to_string(), 
                            signature: signature.to_string(),
                            timestamp
                        };
                        ret.push(node)
                    }
                }
            }
            continue;
        }
        if (mask & MASK_READ_KEY) != 0 {
            mask &= !MASK_READ_KEY;
            if line.starts_with("\"key\": \"") && line.ends_with("\"") {
                key = Some(line.get(8..line.len() - 1).expect("Key").to_string()); 
            }
            continue;
        }
        if (mask & MASK_READ_IP) != 0 {
            mask &= !MASK_READ_IP;
            mask |= MASK_READ_PORT;
            if line.starts_with("\"ip\": ") && line.ends_with(",") {
                let ip_dec: i32 = line.get(6..line.len() - 1).expect("IP").parse().expect("IP");
                let ip_hex: u32 = ip_dec as u32;
                ip = Some(
                    format!(
                        "{}.{}.{}.{}", 
                        (ip_hex >> 24) & 0xFF, (ip_hex >> 16) & 0xFF, 
                        (ip_hex >>  8) & 0xFF, (ip_hex >>  0) & 0xFF
                    )
                ); 
            }
            continue;
        }
        if (mask & MASK_READ_PORT) != 0 {
            mask &= !MASK_READ_PORT;
            if line.starts_with("\"port\": ") {
                let port: u16 = line.get(8..).expect("Port").parse().expect("Port");
                ip = Some(format!("{}:{}", ip.unwrap(), port));
            }
            continue;
        }
    }
    ret 

}

async fn try_other_node(dht: &Arc<DhtNode>, node: &OtherNode) -> Result<Arc<KeyId>> {
    println!("\nTrying DHT peer {}", node.ip.as_str());
    let peer = dht.add_peer_to_network(
        &build_dht_node_info_with_timestamp(
            node.ip.as_str(), 
            node.key.as_str(), 
            node.signature.as_str(),
            node.timestamp
        )?,
        None
    )?.ok_or_else(
        || error!("Cannot add DHT peer {}", node.ip) 
    )?;
    println!("\nDHT peer {} added", node.ip.as_str());
    if !dht.ping_in_network(&peer, None).await? {
        fail!("Cannot ping DHT peer {}", node.ip) 
    }       	
    Ok(peer)
}

async fn select_other_node(dht: &Arc<DhtNode>, other_nodes: &Vec<OtherNode>) -> Arc<KeyId> {
    for other_node in other_nodes.iter() {
        match try_other_node(&dht, other_node).await {
            Ok(peer) => return peer,
            Err(e) => println!("{}", e)
        }
    }
    panic!("Cannot select peer for test")
}

pub struct TestContext {
    pub rt: tokio::runtime::Runtime,
    pub adnl: Arc<AdnlNode>,
    pub dht: Arc<DhtNode>,
    pub overlay: Arc<OverlayNode>, 
    pub overlay_id: Arc<OverlayShortId>,
    pub peer: Arc<KeyId>
}

pub fn init_compatibility_test(
    local_ip_template: &str,
    default_port: u16,
    config_prefix: &str,
    key_tag_dht: usize,
    key_tag_overlay: usize,
    zero_state_file_hash: &str,
    config_file: &str,
    add_overlay: bool,
    add_rldp: bool,
    #[cfg(feature = "dump")] 
    dump_path: Option<&str>
) -> TestContext {

    #[cfg(feature = "dump")]                
    let dump_path = dump_path.map(
        |p| {
            let mut ret = PathBuf::new();
            ret.push(p);
            ret
        }
    );

    let rt = init_test();
    let local_ip = configure_ip(local_ip_template, default_port);
    let key_tags = if key_tag_dht == key_tag_overlay {
        vec![key_tag_dht]
    } else {
        vec![key_tag_dht, key_tag_overlay]
    };
    let config = rt.block_on(
        get_adnl_config(config_prefix, &local_ip, key_tags, true)
    ).unwrap();
    let adnl = rt.block_on(
        AdnlNode::with_config(
            config,
            #[cfg(feature = "dump")]
            dump_path
        )
    ).unwrap();
    let dht = DhtNode::with_params(adnl.clone(), key_tag_dht, None).unwrap();
    let zero_state_file_hash = base64_decode(zero_state_file_hash).unwrap();
    let zero_state_file_hash = zero_state_file_hash.as_slice().try_into().unwrap();
    let overlay = OverlayNode::with_adnl_node_and_zero_state(
        adnl.clone(), 
        zero_state_file_hash,
        key_tag_overlay
    ).unwrap();
    let mut subscribers: Vec<Arc<dyn Subscriber>> = vec![overlay.clone(), dht.clone()];
    if add_rldp {
        subscribers.push(
            RldpNode::with_adnl_node(adnl.clone(), vec![overlay.clone()]).unwrap()
        )
    }
    let overlay_id = overlay.calc_overlay_short_id(
        -1i32, 
        0x8000000000000000u64 as i64
    ).unwrap();
    rt.block_on(
        async {
            AdnlNode::start(&adnl, subscribers).await.unwrap();
            if add_overlay {
                assert!(overlay.add_local_workchain_overlay(None, &overlay_id, None).unwrap());
            }
        }                                   
    );  
    
    let peer = rt.block_on(select_other_node(&dht, &extract_other_nodes(config_file)));
    TestContext {
        rt, 
        adnl, 
        dht, 
        overlay, 
        overlay_id,
        peer
    }

}

// Not all tests use overlay peers
#[allow(dead_code)]
pub fn find_overlay_peer(
    peers: &mut Vec<(IpAddress, NodeOverlay)>,
    ctx_search: &mut Option<OverlayNodesSearchContext>,
    iter: &mut Option<DhtIterator>,
    ctx_test: &mut TestContext,
    log_target: &str
) -> (IpAddress, NodeOverlay) {
    loop {
        while peers.is_empty() {
            log::info!(target: log_target, "---- Search overlay peer...");
            peers.append(
                &mut ctx_test.rt.block_on(
                    DhtNode::find_overlay_nodes_in_network_with_context(
                        &ctx_test.dht, 
                        &ctx_test.overlay_id, 
                        ctx_search,
                        DhtSearchPolicy::FastSearch(5),
                        iter,
                        None
                    )
                ).unwrap()
            )
        }
        let (ip, node) = peers.pop().unwrap();
        if ip.into_udp() == ctx_test.adnl.ip_address().into_udp() {
            continue
        }
        log::info!(
            target: log_target, 
            "---- Try overlay peer {} {:?}, own address {}", 
            ip, node, ctx_test.adnl.ip_address()
        );
        let peer = ctx_test.overlay.add_public_peer(
            &ip, &node, &ctx_test.overlay_id
        ).unwrap().unwrap();
        let found = ctx_test.rt.block_on(
            ctx_test.overlay.get_random_peers(&peer, &ctx_test.overlay_id, None)
        ).unwrap();
        if found.is_some() {
            log::info!(target: log_target, "---- Good overlay peer {} ", peer);
            ctx_test.peer = peer;
            break (ip, node)
        } else {
            log::info!(target: log_target, "---- Bad overlay peer {}", peer);
        }
    }
}

