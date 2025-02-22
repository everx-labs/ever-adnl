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

use adnl::{common::AdnlPeers, node::AdnlNode};
use dht::{DhtNode, DhtSearchPolicy, TARGET};
use overlay::{OverlayNode, OverlayShortId};
use std::{
    future::Future, sync::{Arc, atomic::{AtomicU32, Ordering}}, thread::sleep, 
    time::{Duration, Instant}
};
use ever_block::{fail, base64_encode, KeyOption, Result};

#[path = "./test_utils.rs"]
mod test_utils;
use test_utils::{init_compatibility_test, init_test, get_adnl_config, TestContext};

const KEY_TAG: usize = 0;

const ZEROSTATE_MAINNET: &str = 
    "0nC4eylStbp9qnCq8KjDYb789NjS25L5ZA1UQwcIOOQ=";
const ZEROSTATE_TESTNET: &str = 
    "XplPz01CXAps5qeSWUtxcyBfdAo5zVb1N979KLSKD24=";

const CONFIG_MAINNET_FILE: &str = "tests/config/mainnet.json";
const CONFIG_TESTNET_FILE: &str = "tests/config/testnet.json";

fn init_dht_compatibility_test(
    local_ip_template: &str,
    zero_state_file_hash: &str,
    config_file: &str,
) -> TestContext {
    init_compatibility_test(
        local_ip_template,
        4190,
        "dht",
        KEY_TAG,
        KEY_TAG,
        zero_state_file_hash,
        config_file,
        false,
        false,
        #[cfg(feature = "dump")] 
        None
    )
}

fn init_mainnet_test(local_ip_template: &str) -> TestContext {
    init_dht_compatibility_test(
        local_ip_template, 
        ZEROSTATE_MAINNET,
        CONFIG_MAINNET_FILE
    )
}

fn init_testnet_test(local_ip_template: &str) -> TestContext {
    init_dht_compatibility_test(
        local_ip_template, 
        ZEROSTATE_TESTNET,
        CONFIG_TESTNET_FILE
    )
}

fn init_local_test() -> (
    tokio::runtime::Runtime, 
    Arc<AdnlNode>, 
    Arc<DhtNode>, 
    Arc<OverlayNode>,
    Arc<AdnlNode>, 
    Arc<DhtNode>, 
    Arc<OverlayNode>
) {
    let rt = init_test();
    let config1 = rt.block_on(
        get_adnl_config("dht", "127.0.0.1:4191", vec![KEY_TAG], true)
    ).unwrap();
    let config2 = rt.block_on(
        get_adnl_config("dht", "127.0.0.1:4192", vec![KEY_TAG], true)
    ).unwrap();
    let adnl1 = rt.block_on(AdnlNode::with_config(config1)).unwrap();
    let dht1 = DhtNode::with_params(adnl1.clone(), KEY_TAG, None).unwrap();
    let overlay1 = OverlayNode::with_adnl_node_and_zero_state(
        adnl1.clone(), 
        &[1u8; 32], 
        KEY_TAG
    ).unwrap();
    rt.block_on(AdnlNode::start(&adnl1, vec![dht1.clone(), overlay1.clone()])).unwrap();
    let adnl2 = rt.block_on(AdnlNode::with_config(config2)).unwrap();
    let dht2 = DhtNode::with_params(adnl2.clone(), KEY_TAG, None).unwrap();
    let overlay2 = OverlayNode::with_adnl_node_and_zero_state(
        adnl2.clone(), 
        &[1u8; 32], 
        KEY_TAG
    ).unwrap();
    rt.block_on(AdnlNode::start(&adnl2, vec![dht2.clone(), overlay2.clone()])).unwrap();
    (rt, adnl1, dht1, overlay1, adnl2, dht2, overlay2)
}
               
async fn run_test<F: Future<Output = Result<bool>>>(f: impl Fn() -> F) -> bool {
    for _ in 0..4 {
        if let Ok(true) = f().await {
            return true
        }
    }    
    f().await.unwrap()
}

#[test]
fn dht_compatibility() {
    let ctx = init_testnet_test("0.0.0.0:1");
    ctx.rt.block_on(
        async move {
            let key = ctx.dht.key_of_network(None).unwrap();
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(run_test(|| ctx.dht.find_dht_nodes_in_network(&ctx.peer, None)).await);
            assert!(run_test(|| DhtNode::store_ip_address(&ctx.dht, &key)).await);
            assert!(
                run_test(|| ctx.dht.get_signed_address_list_in_network(&ctx.peer, None)).await
            );  
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(run_test(|| DhtNode::store_ip_address(&ctx.dht, &key)).await);
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(
                run_test(|| ctx.dht.get_signed_address_list_in_network(&ctx.peer, None)).await
            );  
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            assert!(
                run_test(|| ctx.dht.get_signed_address_list_in_network(&ctx.peer, None)).await
            );
            assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            ctx.adnl.stop().await;
    	}
    )
}

/*
fn parse_key_id(key_id: &str) -> Arc<KeyId> {
    let key_id = base64::decode(key_id).unwrap();
    KeyId::from_data(arrayref::array_ref!(key_id, 0, 32).clone())
}
*/

/*
#[test]
fn dht_devnet() {
    let (mut rt, adnl, dht, _, peer) = init_compatibility_test(
        "0.0.0.0:4191",
        "13.49.50.74:30303",
        "+BseD1YGX47BkO++//7VGgrzU2yTtlunki6GMPlwoVc=",
        "P7KF9PrNJQjlhnoU8hnAwSJHtqw29me7N8sPiovdbdtHsILT7yoLwZUjl7iLmwvsByhF9vdxzzI+L3hoCW14Ag==",
        "eYpoU9z6IVIC/PsweFqUHLHRAU8ZoidCGWIA77xuOJg="
    );
    rt.block_on(
        async move { 
            let key_ids = [
                "bC7CwD+VKcF0Ta36zqEE5Yn2zqNnnFUSV+Nq2FYgAvw=",
                "1YSQIxn+TUf6oBADVk2ETzq/YWbBL5BZ2qcfuiPulXo=",
                "CuNe4D/gTwyhW+I58rIhFyLBUBbHiugn32xgNEsW6V0=",
                "OjznBLeyjkHELLZb7OumznG4rGhajwCAhFEwxgimLHM="
            ];
            assert!(run_test(||dht.ping(&peer)).await);
            let dht = Arc::new(dht);
            for key_id in key_ids.iter() {
                let key_id = parse_key_id(key_id);
                let (ip, _) = run_test(||DhtNode::find_address(&dht, &key_id)).await;
                println!("Found IP address: {} -> {}", key_id, ip);
            }
            adnl.stop().await;
    	}
    )
}
*/

#[test]
fn dht_multitask() {
    const THREADS: usize = 200;
    let ctx = init_testnet_test("0.0.0.0:1");
    let ping = Arc::new(tokio::sync::Barrier::new(THREADS + 1));
    let pass = Arc::new(AtomicU32::new(0));
    for i in 0..THREADS {
        let dht = ctx.dht.clone();
        let peer = ctx.peer.clone();
        let ping = ping.clone();
        let pass = pass.clone();
        ctx.rt.spawn(
            async move {
                for _ in 0..20 {
                    if run_test(|| dht.ping_in_network(&peer, None)).await {
                        pass.fetch_add(1, Ordering::Relaxed);
                        break
                    }
                }
                ping.wait().await
            }
        );
        // Ensure channel creation
        let delay = if i < 3 {
            300
        } else {
            30
        };
        sleep(Duration::from_millis(delay));
    }
    ctx.rt.block_on(ping.wait());                                                            
    assert_eq!(pass.load(Ordering::Relaxed), THREADS as u32);
    ctx.rt.block_on(ctx.adnl.stop());
}

async fn test_find_nodes(dht: &Arc<DhtNode>, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
    let mut iter = None;
    let mut pool = Vec::new();
    let mut ctx = None;
    let started = Instant::now();
    loop {
        if started.elapsed().as_secs() > 60 {
            break
        }
        let mut nodes = DhtNode::find_overlay_nodes_in_network_with_context(
            dht, overlay_id, &mut ctx, DhtSearchPolicy::FastSearch(5), &mut iter, None
        ).await?;
        if !nodes.is_empty() {
            pool.append(&mut nodes);
        }
        if let Some(iter) = &iter {
            log::debug!(
                target: TARGET, 
                "Overlay nodes search {}: {} nodes found", 
                iter, pool.len()
            );
        } else {
            log::debug!(target: TARGET, "Overlay nodes search FAST: {} nodes found", pool.len());
            if !nodes.is_empty() { 
                break
            }
        }
    }
/*
    let mut total_pool = Vec::new();
    total_pool.append(&mut pool);
    loop {
        let mut nodes = DhtNode::find_overlay_nodes_with_context(
            dht, overlay_id, &mut ctx, DhtSearchPolicy::FullSearch(5), &mut iter
        ).await?;
        if !nodes.is_empty() {
            pool.append(&mut nodes);
        }
        if let Some(iter) = &iter {
            log::debug!(target: TARGET, "Overlay nodes searh {}: {} nodes found", iter, pool.len());
        } else {
            log::debug!(target: TARGET, "Overlay nodes search FULL: {} nodes found", pool.len());
            break;
        }
    }
*/
    if !pool.is_empty() {
        log::debug!(target: TARGET, "---- Found overlay nodes:");
        for (ip, node) in pool {
            let key: Arc<dyn KeyOption> = (&node.id).try_into()?;
            log::debug!(
                target: TARGET, 
                "\n{} key ID {}, key {}, version {}, signature {}", 
                ip, 
                key.id(),
                base64_encode(key.pub_key()?),
                node.version,
                base64_encode(&node.signature[..])
            );
        }
        Ok(true)
    } else {
        fail!("Cannot find overlay nodes")
    }
}

fn find_overlay_nodes(ctx: &TestContext) {
    ctx.rt.block_on(
        async move { 
            assert!(run_test(|| test_find_nodes(&ctx.dht, &ctx.overlay_id)).await);
            ctx.adnl.stop().await;
        }
    )
}

#[test]
fn find_overlay_nodes_testnet() {
    let ctx = init_testnet_test("0.0.0.0:1");
    find_overlay_nodes(&ctx)
}

#[test]
fn find_overlay_nodes_mainnet() {
    let ctx = init_mainnet_test("0.0.0.0:1");
    find_overlay_nodes(&ctx)
}

#[test]
fn dht_response_mainnet() {
    let ctx = init_mainnet_test("0.0.0.0:1");
    ctx.rt.block_on(
        async move { 
            assert!(
                run_test(|| ctx.dht.get_signed_address_list_in_network(&ctx.peer, None)).await
            );
            assert!(
                run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await
            );
            ctx.adnl.stop().await;
        }
    )    
}

#[test]
fn adnl_reset_channel() {
    let ctx = init_testnet_test("0.0.0.0:1");
    ctx.rt.block_on(
        async move { 
            for _ in 0..10 {
                assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            }
            let peers = AdnlPeers::with_keys(
                ctx.dht.key_of_network(None).unwrap().id().clone(), 
                ctx.peer.clone()
            );
            ctx.adnl.reset_peers(&peers).unwrap();
            for _ in 0..10 {
                assert!(run_test(|| ctx.dht.ping_in_network(&ctx.peer, None)).await);
            }
            ctx.adnl.stop().await;
        }
    )    
}

#[test]                              	
fn dht_session() {
    let (rt, adnl1, dht1, overlay1, adnl2, dht2, overlay2) = init_local_test();
    rt.block_on(
        async move {
            let peer1 = dht2.add_peer_to_network(
                &dht1.get_signed_node_of_network(None).unwrap(),
                None
            ).unwrap().unwrap();
            let peer2 = dht1.add_peer_to_network(
                &dht2.get_signed_node_of_network(None).unwrap(),
                None
            ).unwrap().unwrap();
            assert!(dht1.ping_in_network(&peer2, None).await.unwrap());
            assert!(dht2.ping_in_network(&peer1, None).await.unwrap());
            assert!(dht1.find_dht_nodes_in_network(&peer2, None).await.unwrap());
            assert!(dht2.find_dht_nodes_in_network(&peer1, None).await.unwrap());
            assert!(
                DhtNode::store_ip_address(
                    &dht1, 
                    &dht1.key_of_network(None).unwrap()
                ).await.unwrap()
            );
            assert!(
                DhtNode::store_ip_address(
                    &dht2, 
                    &dht2.key_of_network(None).unwrap()
                ).await.unwrap()
            );  
            let overlay_id = overlay1.calc_overlay_id(
                -1, 
                0x8000000000000000u64 as i64
            ).unwrap();
            let overlay_short_id = overlay1.calc_overlay_short_id(
                -1, 
                0x8000000000000000u64 as i64
            ).unwrap();
            overlay1.add_local_workchain_overlay(None, &overlay_short_id, None).unwrap();
            overlay2.add_local_workchain_overlay(None, &overlay_short_id, None).unwrap();
            let node1 = overlay1.get_signed_node(&overlay_short_id).unwrap();
            let node2 = overlay2.get_signed_node(&overlay_short_id).unwrap();
            assert!(DhtNode::store_overlay_node(&dht1, &overlay_id, &node2).await.unwrap());
            assert!(DhtNode::store_overlay_node(&dht2, &overlay_id, &node1).await.unwrap());  
            adnl1.stop().await;
            adnl2.stop().await;
    	}
    )
}

#[test]
fn dht_store_testnet() {
    let ctx = init_testnet_test("0.0.0.0:1");
    ctx.rt.block_on(
        async move { 
            let overlay_long_id = ctx.overlay.calc_overlay_id(
                -1, 
                0x8000000000000000u64 as i64
            ).unwrap();
            ctx.overlay.add_local_workchain_overlay(None, &ctx.overlay_id, None).unwrap();
            let node = ctx.overlay.get_signed_node(&ctx.overlay_id).unwrap();
            let key = ctx.dht.key_of_network(None).unwrap();
            assert!(run_test(|| DhtNode::store_ip_address(&ctx.dht, &key)).await);
            assert!(
                run_test(||DhtNode::store_overlay_node(&ctx.dht, &overlay_long_id, &node)).await
            );
            ctx.adnl.stop().await;
        }
    )    
}
