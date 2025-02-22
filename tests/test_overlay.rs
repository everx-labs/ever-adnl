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

#![allow(clippy::type_complexity)]

// TO REMOVE AFTER FULL REBRANDING
extern crate adnl as dht;
extern crate adnl as overlay;
extern crate ton_api as ever_api;

use adnl::{
    common::{
        AdnlPeers, Answer, QueryAnswer, QueryResult, Subscriber, TaggedByteSlice, 
        TaggedTlObject
    },
    node::{AdnlNode, IpAddress}, 
    telemetry::{Metric, MetricBuilder, TelemetryItem, TelemetryPrinter}
};
use dht::{DhtIterator, DhtNode, DhtSearchPolicy, OverlayNodesSearchContext}; 
use overlay::{OverlayNode, OverlayShortId, OverlayUtils};
use rand::Rng;
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    cmp::min, convert::TryInto, fs::{File, OpenOptions}, io::{BufRead, BufReader, Read, Write},
    net::SocketAddr, sync::{Arc, atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering}},
    thread::{self, JoinHandle, sleep}, time::{Duration, Instant}
};
#[cfg(feature = "dump")]
use std::path::PathBuf;
use ever_api::{
    deserialize_boxed, Deserializer, IntoBoxed, serialize_boxed, 
    ton::{ //ever::{
        TLObject, 
        overlay::{
            Certificate as OverlayCertificate, Node as NodeOverlayBoxed, 
            broadcast::Broadcast as BroadcastOrd, node::Node as NodeOverlay 
        }, 
        rpc::ton_node/*ever_node*/::GetCapabilities, 
        ton_node/*ever_node*/::capabilities::Capabilities
    }
};
use ever_block::{
    error, fail, 
    base64_decode, base64_encode, Ed25519KeyOption, KeyId, KeyOption, Result, sha256_digest
};

#[path = "./test_utils.rs"]
mod test_utils;
use test_utils::{
    find_overlay_peer, init_compatibility_test, init_test, get_adnl_config, TestContext
};

const KEY_TAG_DHT: usize = 1;
const KEY_TAG_OVERLAY: usize = 2;
const ZERO_STATE: &str = "XplPz01CXAps5qeSWUtxcyBfdAo5zVb1N979KLSKD24=";

const CONFIG_TESTNET_FILE: &str = "tests/config/testnet.json";
const TARGET: &str = "overlay";

/*
pub fn build_dht_node_info_ex(
    ip: &str, 
    key: &str, 
    signature: &str,
    addr_version: i32,
    node_version: i32
) -> Result<Node> {
    let key = base64_decode(key)?;
    if key.len() != 32 {
        fail!("Bad public key length")
    }
    let addrs = vec![IpAddress::from_versioned_string(ip, None)?.into_udp().into_boxed()];
    let signature = base64_decode(signature)?;
    let node = Node {
        id: Ed25519 {
            key: UInt256::with_array(key.try_into().unwrap())
        }.into_boxed(),
        addr_list: AddressList {
            addrs: addrs.into(),
            version: addr_version,
            reinit_date: addr_version,
            priority: 0,
            expire_at: 0
        },
        version: node_version,
        signature
    };
    Ok(node)
}
*/

fn init_overlay_simple_compatibility_test(
    local_ip_template: &str,
    #[cfg(feature = "dump")] 
    dump_path: Option<&str>
) -> TestContext {
    init_compatibility_test(
        local_ip_template,
        4190,
        "overlay",
        KEY_TAG_DHT,
        KEY_TAG_OVERLAY,
        ZERO_STATE,
        CONFIG_TESTNET_FILE,
        true,
        true,
        #[cfg(feature = "dump")] 
        dump_path
    )
}

fn init_overlay_compatibility_test(
    local_ip_template: &str,
    #[cfg(feature = "dump")] 
    dump_path: Option<&str>
) -> (
    TestContext,
    Vec<(IpAddress, NodeOverlay)>,
    Option<OverlayNodesSearchContext>,
    Option<DhtIterator>
) {
    let mut ctx_test = init_overlay_simple_compatibility_test(
        local_ip_template,
        #[cfg(feature = "dump")] 
        dump_path
    );
    let mut ctx_search = None;
    let mut iter = None;
    let mut overlay_peers = Vec::new();
    find_overlay_peer(
        &mut overlay_peers,  
        &mut ctx_search, 
        &mut iter,
        &mut ctx_test,
        TARGET
    );
    log::info!(
        target: TARGET, 
        "Use local key {}", 
        ctx_test.adnl.key_by_tag(KEY_TAG_OVERLAY).unwrap().id()
    );
    (ctx_test, overlay_peers, ctx_search, iter)
}

#[test] 
fn test_overlay_id() {
    let workchain = -1i32;
    let shard = 0x8000000000000000u64 as i64;    
    let file_hash = base64_decode("aAMjutqwMSgcejzVa/OWEHRiECI2i5yxn9FM/Thpa2Q=").unwrap();
    let file_hash = file_hash.as_slice().try_into().unwrap();
    assert_eq!(
        hex::encode(&OverlayUtils::calc_overlay_id(workchain, shard, file_hash).unwrap()),
        "2441f387e2f355d4fd82ffc63d94d98e1d078d8855270a3d3c10c09e0701976f"
    );
    assert_eq!(
        hex::encode(
            OverlayUtils::calc_overlay_short_id(workchain, shard, file_hash).unwrap().data()
        ),
        "dc7c6d60991db081780e7e12627d8c315dc171db982452e91f1f30d738cef966"
    );
}

struct TestConsumer {
    pub received: Arc<AtomicU32>
}

#[async_trait::async_trait]
impl Subscriber for TestConsumer {
    async fn try_consume_query(
        &self, 
        query: TLObject, 
       _peers: &AdnlPeers
    ) -> Result<QueryResult> {
        println!("RECEIVED {:?}", query);
        self.received.fetch_add(1, Ordering::Relaxed);
        let query = match query.downcast::<GetCapabilities>() {
            Ok(_) => {
                let answer = TLObject::new(
                    Capabilities {
                        version: 2,
                        capabilities: 1,
                    }.into_boxed()
                );
                let answer = TaggedTlObject {
                    object: answer,
                    #[cfg(feature = "telemetry")]
                    tag: 0
                };
                return Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Object(answer)))))
            },
            Err(q) => q
        };
        fail!("Unknown query {:?}", query);
    }
}

fn test_random_peers(ctx_test: &TestContext) {
    ctx_test.rt.block_on(
        async move {
            println!("sending getRandomPeers request...");
            let overlay_peers = loop {
                let overlay_peers = ctx_test.overlay
                    .get_random_peers(&ctx_test.peer, &ctx_test.overlay_id, None)
                    .await.unwrap();
                if let Some(overlay_peers) = overlay_peers {
                    break overlay_peers
                }
            };
            println!("received {} overlay peers:", overlay_peers.len());
            assert!(!overlay_peers.is_empty());
            for node in overlay_peers {
                println!("{:?}", node);
                let mut ctx_search = None;
                let key: Arc<dyn KeyOption> = (&node.id).try_into().unwrap();
                let result = DhtNode::find_address_in_network_with_context(
                    &ctx_test.dht, 
                    key.id(),
                    &mut ctx_search,
                    DhtSearchPolicy::FastSearch(5),
                    None
                ).await;
                match result {
                    Ok(Some((ip, _))) => println!("IP {}", ip),
                    Ok(None) => println!("Address not found"),
                    Err(err) => println!("Error {}", err)
                } 
            }
    	}
    )
}

fn test_overlay_broadcast_receive(ctx_test: &TestContext) {

    let get_it = Arc::new(AtomicBool::new(false));
    let received = Arc::new(AtomicU32::new(0));
    ctx_test.overlay.add_consumer(
        &ctx_test.overlay_id, 
        Arc::new(TestConsumer{received: received.clone()})
    ).unwrap();

    log::info!(target: TARGET, "Use overlay peer {} for receiving test", ctx_test.peer);
    let got_it = get_it.clone();
    let overlay = ctx_test.overlay.clone();
    let overlay_id = ctx_test.overlay_id.clone(); 
    ctx_test.rt.spawn(
        async move {
            let now = Instant::now();
            let qty = 25;
            let mut count = 0;
            for _ in 0..qty {
                let recv = overlay.wait_for_broadcast(&overlay_id).await.unwrap().unwrap();
                println!( 
                    "RECEIVED {} bytes FROM OVERLAY {}/{}", 
                    recv.data.len(), overlay_id, recv.recv_from
                );
                count += recv.data.len();
            }
            get_it.store(true, Ordering::Relaxed);
            println!(
                "RECEIVED {} brodcasts ({} bytes) in {} msec", 
                qty, count, now.elapsed().as_millis()
            );
        }
    );

    let mut bad_nodes = std::collections::HashSet::new();
    let mut known_nodes = std::collections::HashSet::new();
    known_nodes.insert(ctx_test.peer.clone());
    let mut peers = vec![ctx_test.peer.clone()];

    ctx_test.rt.block_on(
        async move {
            let start = Instant::now();
            let is_completed = || {
                got_it.load(Ordering::Relaxed) && (received.load(Ordering::Relaxed) >= 3)
            };
            loop {
                if is_completed() {
                    break
                }
                if start.elapsed().as_secs() > 500 {
                    assert!(false)
                }
                let mut new_peers = Vec::new();
                for peer in peers.iter() {
                    if is_completed() {
                        break
                    }
                    if bad_nodes.contains(peer) {
                       continue                                                                    
                    }
                    let nodes = ctx_test.overlay.get_random_peers(
                        peer, &ctx_test.overlay_id, Some(500)
                    ).await.unwrap();
                    let nodes = if let Some(nodes) = nodes {
                        nodes
                    } else {
                        log::info!(target: TARGET, "Mark overlay peer {} bad", peer);
                        bad_nodes.insert(peer.clone());
                        continue
                    };
                    for node in nodes {
                        if is_completed() {
                            break
                        }
                        let key: Arc<dyn KeyOption> = (&node.id).try_into().unwrap();
                        let key_id = key.id();
                        if !known_nodes.contains(key_id) {
                            let mut ctx_search = None;
                            if let Ok(Some((ip, _))) = 
                                DhtNode::find_address_in_network_with_context(
                                    &ctx_test.dht, 
                                    key_id,
                                    &mut ctx_search,
                                    DhtSearchPolicy::FastSearch(5),
                                    None
                            ).await {
                                println!("RECEIVED new overlay node {}", key_id);
                                ctx_test.overlay.add_public_peer(
                                    &ip, &node, &ctx_test.overlay_id
                                ).unwrap();
                                known_nodes.insert(key_id.clone());
                            } else {
                                continue
                            }
                        }
                        new_peers.push(key_id.clone())
                    }
                }
                peers.append(&mut new_peers);
            }
        }
    )

}

fn test_overlay_broadcast_send(ctx_test: &TestContext) {
    ctx_test.rt.block_on(
        async move {
            let mut data = Vec::new();
            for _ in 0..40 {
                let chunk: [u8; 32] = rand::thread_rng().gen();
                data.extend_from_slice(&chunk)
            }
            let data = TaggedByteSlice {
                object: data.as_slice(),
                #[cfg(feature = "telemetry")]
                tag: 0
            };
            assert!(
                ctx_test.overlay.broadcast(
                    &ctx_test.overlay_id, &data, None, false
                ).await.unwrap().send_to > 0
            );
            sleep(Duration::from_millis(1000));
            let data: [u8; 15] = rand::thread_rng().gen();
            let data = TaggedByteSlice {
                object: &data[..],
                #[cfg(feature = "telemetry")]
                tag: 0
            };
            assert!(
                ctx_test.overlay.broadcast(
                    &ctx_test.overlay_id, &data, None, false
                ).await.unwrap().send_to > 0
            );
            sleep(Duration::from_millis(1000));
        }
    )
}

#[test]
fn test_overlay_compatibility() {

    let (ctx_test, _, _, _) = init_overlay_compatibility_test(
        "0.0.0.0:1", 
        #[cfg(feature = "dump")]
        None //Some(".\\target\\01")
    );

    test_random_peers(&ctx_test);
    test_overlay_broadcast_receive(&ctx_test);
    test_overlay_broadcast_send(&ctx_test);

    // Stop
    ctx_test.rt.block_on(
        async move {
            ctx_test.adnl.stop().await;
        }
    )

}

#[ignore]
#[test]
fn test_hang_broadcast_receive() {
    let (ctx_test, _, _, _) = init_overlay_compatibility_test(
        "0.0.0.0:1", 
        #[cfg(feature = "dump")]
        None //Some(".\\target\\01")
    );
    test_overlay_broadcast_receive(&ctx_test);
    ctx_test.rt.block_on(
        async move {
            ctx_test.adnl.stop().await
        }
    ); 
    {
        let (ctx_test, _, _, _) = init_overlay_compatibility_test(
            "0.0.0.0:1", 
            #[cfg(feature = "dump")]
            Some(".\\target\\02")
        );
        ctx_test.rt.block_on(
            async move {
                ctx_test.adnl.stop().await
            }
        ) 
    }
}

#[ignore]
#[test]
fn test_hang_broadcast_send() {
    loop {
        let (ctx_test, _, _, _) = init_overlay_compatibility_test(
            "0.0.0.0:1", 
            #[cfg(feature = "dump")]
            None
        );
        test_overlay_broadcast_send(&ctx_test);
        ctx_test.rt.block_on(
            async move {
                ctx_test.adnl.stop().await;
            }
        );
        println!("NEXT NEXT");
    }
}

pub fn init_local_node(rt: tokio::runtime::Runtime, ip: &str, workers_pool: u8) -> (
    tokio::runtime::Runtime, 
    Arc<AdnlNode>,
    Arc<OverlayNode>, 
    Arc<OverlayShortId>
) {
    let zero_state_file_hash = base64_decode(ZERO_STATE).unwrap();
    let zero_state_file_hash = zero_state_file_hash.as_slice().try_into().unwrap();
    let mut config = rt.block_on(
        get_adnl_config("overlay", ip, vec![KEY_TAG_OVERLAY], true)
    ).unwrap();
    config.set_recv_worker_pools(Some(workers_pool), Some(75)).unwrap();
//    config.set_throughput(Some(10));
    let adnl = rt.block_on(
        AdnlNode::with_config(
            config,
            #[cfg(feature = "dump")] 
            None
        )
    ).unwrap();
    adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
    let overlay = OverlayNode::with_adnl_node_and_zero_state(
        adnl.clone(), 
        zero_state_file_hash,
        KEY_TAG_OVERLAY
    ).unwrap();
    let overlay_id = overlay.calc_overlay_short_id(
        -1i32, 
        0x8000000000000000u64 as i64
    ).unwrap();
    rt.block_on(
        async {
            AdnlNode::start(&adnl, vec![overlay.clone()]).await.unwrap();
            assert!(overlay.add_local_workchain_overlay(None, &overlay_id, Some(2)).unwrap());
        }
    ); 
    (rt, adnl, overlay, overlay_id)
}

/*
#[test]
fn test_overlay_broadcast_propagation() {
    loop {
        test_overlay_broadcast_propagation_()
    }
}
*/

const TIMEOUT_BROADCAST_SEC: u64 = 45;
const SUCCESS_RATIO: f32 = 0.95;

struct RunResult {
    elapsed: u32,
    bcast_totally: u32, 
    query_totally: u32, 
    query_average: u32
}

fn run_propagation(
    nodes: &Vec<(tokio::runtime::Runtime, Arc<AdnlNode>, Arc<OverlayNode>, Arc<OverlayShortId>)>,
    neighbours: &[Arc<Vec<Arc<KeyId>>>]
) -> RunResult {

    const LEN: usize = 1024768;
    const STEPS: usize = 1;

    println!("\n==========\n\n");

    let nodes_len = nodes.len();
    let start = Instant::now();
    let ping = Arc::new(tokio::sync::Barrier::new(3 * nodes_len + 1));
    let sync = Arc::new(AtomicU32::new(0));
    let bcast_totally = Arc::new(AtomicU32::new(0));
    let bcast_success = Arc::new(AtomicU32::new(0)); 
    let query_totally = Arc::new(AtomicU32::new(0));
    let query_success = Arc::new(AtomicU32::new(0)); 
    let query_elapsed = Arc::new(AtomicU32::new(0)); 

    for i in 0..nodes_len {

        let (rt, adnl, node, overlay_id) = &nodes[i];
        adnl.check();

        let node = node.clone();
        let overlay_id = overlay_id.clone();
        let adnl_id = adnl.key_by_tag(KEY_TAG_OVERLAY).unwrap().id().clone();
        let adnl = adnl.clone();
        let sync = sync.clone();
        let neighbours = neighbours[i].clone();
        let bcast_totally = bcast_totally.clone();
        let bcast_success = bcast_success.clone();
        let query_totally = query_totally.clone();
        let query_success = query_success.clone();
        let query_elapsed = query_elapsed.clone();

        let overlay_id_send = overlay_id.clone();
        let adnl_id_send = adnl_id.clone();
        let node_send = node.clone();
        let pong = ping.clone();
        rt.spawn(
            async move {
                let mut data = Vec::new();
                data.resize(LEN, 0u8);
                for j in 0..STEPS {
                    data[0] = i as u8;
                    data[1] = j as u8;
                    {
                        let mut rng = rand::thread_rng();
                        for k in 2..LEN - 32 {
                            if k % 16 == 0 {
                                data[k] = 0xFF
                            } else if k % 16 == 8 {
                                data[k] = 0x01
                            } else {
                                data[k] = rng.gen()
                            }
                        }
                    }
                    let hash = sha256_digest(&data[..LEN - 32]);
                    for k in 0..32 {
                        data[LEN - 32 + k] = hash[k]
                    }
                    let data = TaggedByteSlice {
                        object: data.as_slice(),
                        #[cfg(feature = "telemetry")]
                        tag: 0
                    };
                    let info = node_send.broadcast(
                        &overlay_id_send, 
                        &data, 
                        None,
                        false
                    ).await.unwrap();
                    assert_eq!(info.send_to as usize, min(6, nodes_len - 1));
                    println!(
                        "==========\nBroadcasting {} packets by {}/{}, step {}\n", 
                        info.packets, adnl_id_send, adnl.ip_address(), j
                    );
                    bcast_totally.fetch_add(1, Ordering::Relaxed);   
                }
                pong.wait().await;
            }
        );

        let overlay_id_send = overlay_id.clone();
        let adnl_id_send = adnl_id.clone();
        let node_send = node.clone();
        let pong = ping.clone();
        rt.spawn(
            async move {
                for _j in 0..STEPS {
                    let start = Instant::now();
                    while start.elapsed().as_millis() < 10000 {
                        for neighbour in neighbours.iter() {
                            let start1 = start.elapsed().as_millis();
                            println!(
                                "======= {} Sending random peers query to {}", 
                                adnl_id_send, neighbour
                            );
                            query_totally.fetch_add(1, Ordering::Relaxed);   
                            let res = node_send.get_random_peers(
                                neighbour, &overlay_id_send, None
                            ).await;
                            let elapsed = (start.elapsed().as_millis() - start1) as u32;
                            println!(
                                "==========\n{} Got random peers from {}: {:?} in {} ms\n", 
                                adnl_id_send, neighbour, res, elapsed
                            );
                            query_elapsed.fetch_add(elapsed, Ordering::Relaxed);
                            if let Ok(Some(_)) = res {
                                query_success.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }    
                }
                pong.wait().await;
            }
        );

        let pong = ping.clone();
        rt.spawn(
            async move {
                for j in 0..STEPS {
                    let mut mask = 1u64 << i;
                    for _ in 0..nodes_len - 1 {
                        tokio::select! {
                            recv = node.wait_for_broadcast(&overlay_id) => {
                                let recv = recv.unwrap().unwrap();
                                assert_eq!(recv.data.len(), LEN);
                                println!("{:=<10}", "");
                                println!(
                                    "Finished {} with {} packets from {} in {} ms, step {}\n",
                                    adnl_id, recv.packets, recv.recv_from, 
                                    start.elapsed().as_millis(), j
                                );                        
                                let y = recv.data[0];
                                assert_eq!(recv.data[1], j as u8); // jj as u8);
                                let hash = sha256_digest(&recv.data[..LEN - 32]);
                                for k in 0..32 {
                                    assert_eq!(recv.data[LEN - 32 + k], hash[k])
                                }
                                mask |= 1 << (y & 0x0F);
                            },
                            _ = tokio::time::sleep(
                                Duration::from_secs(TIMEOUT_BROADCAST_SEC)
                            ) => {},
                        }
                    }
                    sync.fetch_or(1 << i, Ordering::Relaxed);
                    if mask == ((1 << nodes_len) - 1) {
                        bcast_success.fetch_add(1, Ordering::Relaxed);
                    }
                    println!(
                        "==========\nFinished {} in {} ms, step {}\n", 
                        adnl_id, start.elapsed().as_millis(), j
                    );
                }
                pong.wait().await;
            }
        );

/*
        rt.spawn(
            async move {
                while sync_trace.load(Ordering::Relaxed) != (1 << NODES) -1 {
                    tokio::time::sleep(Duration::from_millis(2000)).await;
                    println!(
                        "==========\nTrace {}: {:x}\n", 
                        adnl_id_trace, 
                        node_trace.get_debug_trace(&overlay_id_trace).unwrap()
                    )
                }
            }
        );
*/

    }

    let (rt, _, _, _) = &nodes[0];
    rt.block_on(ping.wait());
    let elapsed = start.elapsed().as_millis() as u32;
    println!("==========\nElapsed {} ms\n", elapsed);
    let bcast_totally = bcast_totally.load(Ordering::Relaxed);
    let bcast_success = bcast_success.load(Ordering::Relaxed);
    let bcast_quality = bcast_success as f32 / bcast_totally as f32;
    let query_totally = query_totally.load(Ordering::Relaxed);
    let query_success = query_success.load(Ordering::Relaxed);
    let query_quality = query_success as f32 / query_totally as f32;
    println!(
        "==========\nBroadcasts {}/{} success ({})\n", 
        bcast_success, bcast_totally, bcast_quality
    );
    println!(
        "==========\nQueries {}/{} success ({})\n", 
        query_success, query_totally, query_quality
    );
    assert!(SUCCESS_RATIO < bcast_quality);
    assert!(SUCCESS_RATIO < query_quality);
    RunResult {
        elapsed,
        bcast_totally,
        query_totally,
        query_average: query_elapsed.load(Ordering::Relaxed) / query_totally
    }

}

#[test]
fn test_broadcast_propagation() {

/*
    const IP: [&str; 9] = [
        "127.0.0.1:4181",
        "127.0.0.1:4182",
        "127.0.0.1:4183",
        "127.0.0.1:4184",
        "127.0.0.1:4185",
        "127.0.0.1:4186",
        "127.0.0.1:4187",
        "127.0.0.1:4188",
        "127.0.0.1:4189"
    ];
*/
    const IP: [&str; 5] = [
        "127.0.0.1:4181",
        "127.0.0.1:4182",                                                                                                                                                               
        "127.0.0.1:4183",
        "127.0.0.1:4184",
        "127.0.0.1:4185"
    ];
    const NODES: usize = IP.len();

    init_test();
    let mut nodes = Vec::new();
    for ip in IP {
        let rt = tokio::runtime::Runtime::new().unwrap();
        nodes.push(init_local_node(rt, ip, 100 / NODES as u8));
    }
    let mut neighbours = Vec::new();
    for i in 0..NODES {
        let (rt, _, node, overlay_id) = &nodes[i];
        let mut tmp = Vec::new();
        for j in 0..min(6, NODES - 1) {
            let mut j = j + i + 1;
            if j >= NODES {
                j -= NODES
            }
            let (_, _, other_node, _) = &nodes[j];
            let signed_node = other_node.get_signed_node(overlay_id).unwrap();
            let ip = IpAddress::from_versioned_string(IP[j], None).unwrap();
            let dst = node.add_public_peer(&ip, &signed_node, overlay_id).unwrap().unwrap();
            rt.block_on(node.get_random_peers(&dst, overlay_id, None)).unwrap();
            tmp.push(dst);
        }
        neighbours.push(Arc::new(tmp));
    }

    sleep(Duration::from_millis(2000));
    let mut avg_elapsed = 0;
    let mut avg_bcasts  = 0;
    let mut avg_queries = 0;
    let mut avg_average = 0;
    let mut avg_counted = 0;
    while avg_counted < 3 {
        let res = run_propagation(&nodes, &neighbours);
        let elapsed  = (res.elapsed as i32 - avg_elapsed) / (avg_counted + 1);
        let bcasts   = (res.bcast_totally as i32 - avg_bcasts) / (avg_counted + 1);
        let queries  = (res.query_totally as i32 - avg_queries) / (avg_counted + 1);
        let average  = (res.query_average as i32 - avg_average) / (avg_counted + 1);
        avg_elapsed += elapsed;
        avg_bcasts  += bcasts;
        avg_queries += queries;
        avg_average += average;
        avg_counted += 1;
        println!(
            "==== \nAverage({} attempts): \
             elapsed {} ms, broadcasts {}, queries {}, average query time {} ms\n",
            avg_counted, 
            avg_elapsed, 
            avg_bcasts,
            avg_queries,
            avg_average
        );
        assert!((avg_elapsed as u64) < (TIMEOUT_BROADCAST_SEC + 1) * 1000);
        sleep(Duration::from_millis(10000));
    }

    #[cfg(feature = "telemetry")]
    for (_, _, node, _) in nodes.iter() {
        node.stats().unwrap();
    }
    for (rt, adnl, _, _) in nodes.iter() {
        rt.block_on(adnl.stop());
    }
           
}

#[ignore]
#[test]
fn test_overlay_ping() {
 
    const FILE: &str = "ping";

    async fn load_peer(
        overlay: &Arc<OverlayNode>, 
        overlay_id: &Arc<OverlayShortId>, 
        peer: &String
    ) -> Result<Arc<KeyId>> {
        let data: Vec<&str> = peer.split(' ').collect();
        if data.len() != 2 {
            fail!("Bad saved peer {}", peer)
        }
        let node = deserialize_boxed(&base64_decode(data[0])?)?
            .downcast::<NodeOverlayBoxed>()
            .map_err(|_| error!("Bad node in saved peer {}", peer))?;
        let ip = IpAddress::from_versioned_string(data[1], None)?;
        test_peer(overlay, overlay_id, &ip, node).await
    } 

    async fn test_peer(
        overlay: &Arc<OverlayNode>, 
        overlay_id: &Arc<OverlayShortId>, 
        ip: &IpAddress, 
        node: NodeOverlayBoxed
    ) -> Result<Arc<KeyId>> {
        if let Some(peer) = overlay.add_public_peer(ip, &node.only(), &overlay_id)? {
            if overlay.get_random_peers(&peer, &overlay_id, None).await?.is_some() {
                return Ok(peer)
            } 
        }
        fail!("Fail to add peer {}", ip)
    }                               

    println!("\ninitializing...");
    let (mut ctx_test, _, _, _) = init_overlay_compatibility_test(
        "0.0.0.0:1", 
        #[cfg(feature = "dump")]
        None
    );
    ctx_test.rt.block_on(
        async move {
            println!("gathering random peers...");
            let mut peers = Vec::new();
            if let Ok(file) = File::open(FILE) {
                for line in BufReader::new(file).lines() {
                    if let Ok(line) = line {
                        if let Ok(peer) = load_peer(
                            &ctx_test.overlay, &ctx_test.overlay_id, &line
                        ).await {
                            if !peers.contains(&peer) {
                                peers.push(peer)
                            }
                        }
                    }    
                }
            }
            loop {
                if peers.len() >= 48 {
                    break
                }  
                let overlay_peers = loop {
                    let overlay_peers = ctx_test.overlay
                        .get_random_peers(&ctx_test.peer, &ctx_test.overlay_id, None)
                        .await.unwrap();
                    if let Some(overlay_peers) = overlay_peers {
                        break overlay_peers
                    }
                };
                println!("received {} overlay peers:", overlay_peers.len());
                for node in overlay_peers {
                    println!("{:?}", node);
                    let mut ctx_search = None;
                    let key: Arc<dyn KeyOption> = (&node.id).try_into().unwrap();
                    let result = DhtNode::find_address_in_network_with_context(
                        &ctx_test.dht, 
                        key.id(),
                        &mut ctx_search,
                        DhtSearchPolicy::FastSearch(5),
                        None
                    ).await;
                    match result {
                        Ok(Some((ip, _))) => {
                            println!("IP {}", ip);
                            let node = node.into_boxed();
                            let node_encoded = base64_encode(&serialize_boxed(&node).unwrap());
                            if let Ok(peer) = test_peer(
                                &ctx_test.overlay, &ctx_test.overlay_id, &ip, node
                            ).await {   
                                if !peers.contains(&peer) {
                                    let mut file = OpenOptions::new()
                                        .create(true)
                                        .write(true)
                                        .append(true)
                                        .open(FILE)
                                        .unwrap();
                                    writeln!(file, "{} {}", node_encoded, ip).unwrap();
                                    peers.push(peer);
                                }
                            }
                        },
                        Ok(None) => println!("Address not found"),
                        Err(err) => println!("Error {}", err)
                    }
                }
                if !peers.is_empty() {
                    ctx_test.peer = peers[peers.len() - 1].clone()
                }
            }
//            let ping = Arc::new(tokio::sync::Barrier::new(peers.len() + 1));
            let mut stat = Vec::new();
            let mark = Arc::new(Instant::now());
            for peer in peers {
                let peer = peer.clone();
                let overlay_id = ctx_test.overlay_id.clone();
                let overlay = ctx_test.overlay.clone();
                let mark = mark.clone();
                let pong = Arc::new(AtomicU64::new(mark.elapsed().as_millis() as u64));
                stat.push((peer.clone(), pong.clone()));
                tokio::spawn(
                    async move {
                        let query = TLObject::new(GetCapabilities);
                        let query = TaggedTlObject {
                            object: query,
                            #[cfg(feature = "telemetry")]
                            tag: 0
                        };
                        loop {
                            #[allow(clippy::single_match)]
                            match overlay.query(&peer, &query, &overlay_id, None).await {
                                Ok(Some(_answer)) => {
//                                    let caps: CapabilitiesBoxed = Query::parse(answer, &query).unwrap();
//                                    println!("Got capabilities from {}: {:?}", peer, caps);
                                },
                                _ => ()//println!("No capabilities from {}", peer)
                            }
                            pong.store(mark.elapsed().as_millis() as u64, Ordering::Relaxed);
                        }
                    }
                );
            }
//            ping.wait().await;
            loop {
                for s in stat.iter() {
                    let (peer, pong) = s;
                    let diff = (mark.elapsed().as_millis() as i64 - pong.load(Ordering::Relaxed) as i64).abs();
                    if diff > 5000 {
                        println!("Ping {} seems to be hang ({}ms)", peer, diff);
                    }
                }
                sleep(Duration::from_millis(1000))
            }
//            adnl.stop().await;
    	}
    )

}

fn node(src: &str, dst: &str, sync: Arc<AtomicU16>, mask: u16, wait: u16) -> Result<()> {
    let src: SocketAddr = src.parse()?;
    let dst: SocketAddr = dst.parse()?;
    let socket = Socket::new(Domain::ipv4(), Type::dgram(), None)?;
//    socket.set_send_buffer_size(1 << 28)?;
    socket.set_recv_buffer_size(1 << 30)?;
    socket.set_nonblocking(true)?;
    socket.bind(&src.into())?;
    let sync_send = sync.clone();
    let socket_send = socket.try_clone()?;
    thread::spawn(
        move || {
            while sync_send.load(Ordering::Relaxed) != wait {
                thread::sleep(Duration::from_millis(1));
            }
            let dst: SockAddr = dst.into();
            let mut buf = [0; 1024];
            for i in 0..1000000 {
                buf[0] = (i >> 16) as u8;
                buf[1] = (i >>  8) as u8;
                buf[2] = (i >>  0) as u8;
                let size = loop {
                    match socket_send.send_to(&buf, &dst) {
                        Ok(size) => break size,
                        Err(err) => match err.kind() {
                            std::io::ErrorKind::WouldBlock => continue,
                            _ => panic!("Error SEND {:?}", err)
                        }
                    }
                };
                if size != 1024 {
                    panic!("Bad send size {}, expected 1024", size);
                }
            }
        }
    );
    sync.fetch_or(mask, Ordering::Relaxed);
    let mut buf = [0; 1024];
//    let wait = Metric::with_name("wait recv, ns");
    for i in 0..1000000 {
        
        let size = loop {
            match socket.recv(&mut buf) {
                Ok(size) => break size,
                Err(err) => match err.kind() {
                    std::io::ErrorKind::WouldBlock => continue,
                    _ => panic!("Error RECV {:?}", err)
                }
            }
        };
        if size != 1024 {
            panic!("Bad recv size {}, expected 1024", size);
        }
        if buf[0] != ((i >> 16) as u8) {
            panic!("Bad seqno {:02x}{:02x}{:02x}, expected {:06x}", buf[0], buf[1], buf[2], i);
        }
        if buf[1] != ((i >>  8) as u8) {
            panic!("Bad seqno {:02x}{:02x}{:02x}, expected {:06x}", buf[0], buf[1], buf[2], i);
        }
        if buf[2] != ((i >>  0) as u8) {
            panic!("Bad seqno {:02x}{:02x}{:02x}, expected {:06x}", buf[0], buf[1], buf[2], i);
        }
    }
    Ok(())
}

#[ignore]
#[test]
fn test_network() {

    fn start(
        sync: &Arc<AtomicU16>, 
        src: &'static str, 
        dst: &'static str, 
        mask: u16
    ) -> JoinHandle<Result<()>> {
        let sync = sync.clone();
        thread::spawn(move || node(src, dst, sync, mask, 0x01FF))
    }

    fn check(h: JoinHandle<Result<()>>, name: &str) {
        match h.join() {
            Ok(k) => println!("{} ok {:?}", name, k),
            Err(e) => println!("{} failed {:?}", name, e)
        }
    }

    const NODE1: &str = "127.0.0.1:4191";
    const NODE2: &str = "127.0.0.1:4192";
    const NODE3: &str = "127.0.0.1:4193";
    const NODE4: &str = "127.0.0.1:4194";
    const NODE5: &str = "127.0.0.1:4195";
    const NODE6: &str = "127.0.0.1:4196";
    const NODE7: &str = "127.0.0.1:4197";
    const NODE8: &str = "127.0.0.1:4198";
    const NODE9: &str = "127.0.0.1:4199";

    let sync = Arc::new(AtomicU16::new(0));
    let begin = Instant::now();
    let h1 = start(&sync, NODE1, NODE2, 0x0001);
    let h2 = start(&sync, NODE2, NODE3, 0x0002);
    let h3 = start(&sync, NODE3, NODE4, 0x0004);
    let h4 = start(&sync, NODE4, NODE5, 0x0008);
    let h5 = start(&sync, NODE5, NODE6, 0x0010);
    let h6 = start(&sync, NODE6, NODE7, 0x0020);
    let h7 = start(&sync, NODE7, NODE8, 0x0040);
    let h8 = start(&sync, NODE8, NODE9, 0x0080);
    let h9 = start(&sync, NODE9, NODE1, 0x0100);

    println!();
    check(h1, "1st");
    check(h2, "2nd");
    check(h3, "3rd");
    check(h4, "4th");
    check(h5, "5th");
    check(h6, "6th");
    check(h7, "7th");
    check(h8, "8th");
    check(h9, "9th");
    println!("Elapsed {} ms", begin.elapsed().as_millis());

}

#[test]
fn test_metric() {
    init_test();
    const PERIOD: u64 = 5;
    let builder = MetricBuilder::with_metric_and_period(
        Metric::without_totals("metric", PERIOD),
        1000000000
    );
    let printer = TelemetryPrinter::with_params(
        5, 
        vec![TelemetryItem::MetricBuilder(builder.clone())]
    );
    for i in 0..39 {
        if i % 3 == 0 {
            sleep(Duration::from_millis(500));
            builder.update(1);
            sleep(Duration::from_millis(500));
        } else if i % 3 == 1 {
            sleep(Duration::from_millis(100));
            builder.update(1);
            sleep(Duration::from_millis(300));
            builder.update(1);
            sleep(Duration::from_millis(300));
            builder.update(2);
            sleep(Duration::from_millis(200));
            builder.update(1);
            sleep(Duration::from_millis(100));
        } else {
            sleep(Duration::from_millis(100));
            builder.update(1);
            sleep(Duration::from_millis(200));
            builder.update(1);
            sleep(Duration::from_millis(300));
            builder.update(1);
            sleep(Duration::from_millis(200));
            builder.update(1);
            sleep(Duration::from_millis(100));
            builder.update(2);
            sleep(Duration::from_millis(100));
        }
        printer.try_print();
        if i > PERIOD {
            match builder.metric().get_average() {
                3 | 4 => (),
                x => {
                    println!("Average {}, expected 3 or 4", x);
                    assert!(false)
                }
            }
            assert_eq!(builder.metric().maximum(), 6);
        }
    }
}

#[test]
fn test_stop() {
    let ctx_test = init_overlay_simple_compatibility_test(
        "0.0.0.0:1", 
        #[cfg(feature = "dump")]
        None
    );
    let overlay_id = KeyId::from_data([0xCC; 32]);
    let added = ctx_test.overlay.add_private_overlay(
        Some(ctx_test.rt.handle().clone()), 
        &overlay_id, 
        &ctx_test.adnl.key_by_tag(KEY_TAG_OVERLAY).unwrap(),
        &Vec::new(),
        None
    ).unwrap();
    assert!(added);
    let overlay_cloned = ctx_test.overlay.clone();
    let overlay_id_cloned = overlay_id.clone();
    ctx_test.rt.spawn(
        async move {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            let dropped = overlay_cloned.delete_private_overlay(&overlay_id_cloned).unwrap();
            assert!(dropped)
        }
    );
    ctx_test.rt.block_on(
        async move {
            let wait = ctx_test.overlay.wait_for_broadcast(&overlay_id).await.unwrap();
            assert!(wait.is_none())
        }
    )
}

#[ignore]
#[test]
fn test_drop() {

    fn remove(map: Arc<lockfree::map::Map<u8, Arc<u8>>>) {
        let map_cloned = map.clone();
        if let Some(item) = map.get(&0) {
            thread::spawn(
                move || {
                    if let Some(removed) = map_cloned.remove(&0) {
                        println!("drop1 {}", Arc::strong_count(removed.val()));
                    }
                }
            ).join().ok();
            println!("drop2 {}", Arc::strong_count(item.val()));
        }
//        if let Some(item) = map.get(&0) {
//            println!("drop3 {}", Arc::strong_count(item.val()));
//        }
    }

    let map = Arc::new(lockfree::map::Map::new());
    let item = Arc::new(0);
    map.insert(0, item.clone());
    remove(map.clone());
/*
    map.insert(0, item.clone());
    remove(map.clone());
    map.insert(0, item.clone());
    remove(map.clone());
    map.insert(0, item.clone());
    remove(map.clone());
    map.insert(0, item.clone());
    remove(map.clone());
*/
    println!("drop final {}", Arc::strong_count(&item));

}

#[test]
fn test_new_broadcast() {
    const HOPS: u8 = 5;
    let src = Ed25519KeyOption::generate().unwrap();
    let bcast = BroadcastOrd {
        src: (&src).try_into().unwrap(),
        certificate: OverlayCertificate::Overlay_EmptyCertificate,
        flags: 0,
        data: vec![3; 100].into(),
        date: 0,
        signature: vec![2; 32].into()
    }.into_boxed();
    let mut buf = serialize_boxed(&bcast).unwrap();
    buf.extend_from_slice(&[HOPS]);
    let mut reader = &buf[..];
    let obj = Deserializer::new(&mut reader).read_boxed::<TLObject>();
    println!("obj {:?}", obj);
    let mut tag = Vec::new();
    reader.read_to_end(&mut tag).unwrap();
    assert_eq!(tag, vec![HOPS]);
}
