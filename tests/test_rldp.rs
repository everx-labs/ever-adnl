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

use adnl::{
    common::{
        AdnlPeers, Answer, QueryAnswer, QueryResult, Subscriber, TaggedByteSlice, 
        TaggedByteVec
    },
    node::{AdnlNode, IpAddress}
};
use rldp::RldpNode;
use dht::{DhtIterator, OverlayNodesSearchContext};
use overlay::OverlayUtils;
use std::{convert::TryInto, io::Write, path::Path, sync::Arc};
use ever_api::{
    BoxedSerialize, serialize_boxed, serialize_boxed_append,
    ton::{ //ever::{
        TLObject,
        overlay::node::Node as NodeOverlay, 
        rpc::{overlay::Query as OverlayQuery, ton_node/*ever_node*/::DownloadZeroState}
    },
};
use ever_block::{BlockIdExt, ShardIdent};
use ever_block::{base64_decode, KeyId, KeyOption, read_boc, sha256_digest, Result, UInt256};

#[path = "./test_utils.rs"]
mod test_utils;
use test_utils::{
    init_compatibility_test, init_test, find_overlay_peer, get_adnl_config, TestContext
};

const KEY_TAG: usize = 0;
const TARGET: &str = "rldp";
const CONFIG_TESTNET_FILE: &str = "tests/config/testnet.json";
const ZEROSTATE_FILE_HASH: &str = "0nC4eylStbp9qnCq8KjDYb789NjS25L5ZA1UQwcIOOQ=";
const ZEROSTATE_ROOT_HASH: &str = "WP/KGheNr/cF3lQhblQzyb0ufYUAcNM004mXhHq56EU=";

fn init_rldp_compatibility_test(local_ip_template: &str) -> (
    TestContext,
    Arc<AdnlNode>,
    Arc<RldpNode>
) {
    let ctx_test = init_compatibility_test(
        local_ip_template,
        4190,
        "rldp",
        KEY_TAG,
        KEY_TAG,
        ZEROSTATE_FILE_HASH,
        CONFIG_TESTNET_FILE,
        true,
        false,
        #[cfg(feature = "dump")] 
        None
    );
    let ours_ip = format!("{}", ctx_test.adnl.ip_address());
    let pos = ours_ip.find(":").unwrap();
    let ours_ip = format!(
        "{}:{}", 
        &ours_ip[..pos], ctx_test.adnl.ip_address().into_udp().port + 1
    );
    let config = ctx_test.rt.block_on(
        get_adnl_config("rldp", &ours_ip, vec![KEY_TAG], true)
    ).unwrap();
    let adnl = ctx_test.rt.block_on(AdnlNode::with_config(config)).unwrap();
    let rldp = RldpNode::with_adnl_node(adnl.clone(), vec![]).unwrap();
    ctx_test.rt.block_on(AdnlNode::start(&adnl, vec![rldp.clone()])).unwrap();
    (ctx_test, adnl, rldp)
}

fn find_rldp_peer(
    adnl: &Arc<AdnlNode>,
    overlay_peers: &mut Vec<(IpAddress, NodeOverlay)>,
    ctx_search: &mut Option<OverlayNodesSearchContext>,
    iter: &mut Option<DhtIterator>,
    ctx_test: &mut TestContext
) -> (Arc<KeyId>, Arc<KeyId>) {
    let (peer_ip, peer_node) = find_overlay_peer(
        overlay_peers,  
        ctx_search, 
        iter,
        ctx_test,
        TARGET
    );
    let ours_id = adnl.key_by_tag(KEY_TAG).unwrap().id().clone();
    let peer_key: Arc<dyn KeyOption> = (&peer_node.id).try_into().unwrap();
    let peer_id = adnl.add_peer(&ours_id, &peer_ip, &peer_key).unwrap().unwrap();
    (peer_id, ours_id)                                                                 
}

pub struct Mockup;

fn build_reply() -> Vec<u8> {
    let mut reply = Vec::with_capacity(512*1024);
    for i in 0..512*1024 {
        reply.push(i as u8)
    } 
//  reply.resize(512*1024, 0xBBu8);
    reply
}

#[async_trait::async_trait]
impl Subscriber for Mockup {
    async fn try_consume_query(
        &self, 
        object: TLObject, 
        _peers: &AdnlPeers
    ) -> Result<QueryResult> {
        match object.downcast::<OverlayQuery>() { 
            Ok(msg) => {
                assert_eq!(*msg.overlay.as_slice(), [0xAAu8; 32]);
                let reply = TaggedByteVec {
                    object: build_reply(),
                    #[cfg(feature = "telemetry")]
                    tag: 0
                };
                Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(reply)))))
            },
            Err(object) => Ok(QueryResult::Rejected(object))
        }
    }    
}

fn init_local_test() -> (
    tokio::runtime::Runtime, 
    Arc<AdnlNode>, 
    Arc<RldpNode>, 
    Arc<KeyId>,
    Arc<AdnlNode>, 
    Arc<RldpNode>,
    Arc<KeyId>
) {
    let rt = init_test();
    let config1 = rt.block_on(
        get_adnl_config("rldp", "127.0.0.1:4191", vec![KEY_TAG], true)
    ).unwrap();
    let config2 = rt.block_on(
        get_adnl_config("rldp", "127.0.0.1:4192", vec![KEY_TAG], true)
    ).unwrap();
    let adnl1 = rt.block_on(AdnlNode::with_config(config1)).unwrap();
    let rldp1 = RldpNode::with_adnl_node(adnl1.clone(), vec![Arc::new(Mockup)]).unwrap();
    rt.block_on(AdnlNode::start(&adnl1, vec![rldp1.clone()])).unwrap();
    let adnl2 = rt.block_on(AdnlNode::with_config(config2)).unwrap();
    let rldp2 = RldpNode::with_adnl_node(adnl2.clone(), vec![Arc::new(Mockup)]).unwrap();
    rt.block_on(AdnlNode::start(&adnl2, vec![rldp2.clone()])).unwrap();
    let peer1 = adnl1.key_by_tag(KEY_TAG).unwrap(); 
    let peer2 = adnl2.key_by_tag(KEY_TAG).unwrap(); 
    adnl1.add_peer(peer1.id(), adnl2.ip_address(), &peer2).unwrap();
    adnl2.add_peer(peer2.id(), adnl1.ip_address(), &peer1).unwrap();
    (rt, adnl1, rldp1, peer1.id().clone(), adnl2, rldp2, peer2.id().clone())
}

async fn download_by_block_id<T: BoxedSerialize>(
    rldp: &Arc<RldpNode>, 
    peer: &Arc<KeyId>, 
    ours: &Arc<KeyId>, 
    root: &str, 
    file: &str, 
    seqno: i32, 
    prefix: &[u8],
    callback: impl Fn(BlockIdExt) -> (T, String)
) -> bool {
    let root_hash = base64_decode(root).unwrap();
    let file_hash = base64_decode(file).unwrap();
    let file_hash: [u8; 32] = file_hash.try_into().unwrap();
    let mut query = prefix.to_vec();
    let block = BlockIdExt {
        shard_id: ShardIdent::with_tagged_prefix(
            -1, 0x8000000000000000u64 as i64 as u64
        ).unwrap(),
        seq_no: seqno as u32,
        root_hash: UInt256::with_array(root_hash.try_into().unwrap()),
        file_hash: UInt256::with_array(file_hash.clone())
    };
    let (message, title) = callback(block);
    serialize_boxed_append(&mut query, &message).unwrap();
    send_rldp_query(
        rldp, 
        peer, 
        ours, 
        &query, 
        &title, 
        Some(&file_hash)
    ).await
}

async fn send_rldp_query(
    rldp: &Arc<RldpNode>, 
    dst: &Arc<KeyId>, 
    src: &Arc<KeyId>, 
    query: &[u8], 
    msg: &str, 
    hash: Option<&[u8]>
) -> bool {
    const ATTEMPTS: u32 = 10;
    let mut i: u32 = 0;
    let now = std::time::SystemTime::now();
    for _ in 0..ATTEMPTS {
        i += 1;
        log::info!(target:TARGET, "{}, attempt {}", msg, i);
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        if let (Some(answer), _) = rldp.query(
            &TaggedByteSlice {
                object: query,
                #[cfg(feature = "telemetry")]
                tag: 0
            },
            None, 
            &peers, 
            Some(10000)
        ).await.unwrap() {
            log::info!(target:TARGET, "Totally received {} bytes", answer.len());
            let path = Path::new("target").join(msg);
            let mut file = std::fs::File::create(path).unwrap();
            file.write_all(&answer[..]).unwrap();
            if let Some(hash) = hash {
                assert!(sha256_digest(&answer[..]).eq(&hash[..]));
            } else {
                read_boc(answer).unwrap();
            }
            break;
        }
    }
    if i < ATTEMPTS {
        log::info!(target:TARGET, "Elapsed {}ms", now.elapsed().unwrap().as_millis());
        true
    } else {
        false
    }
}

#[test]
fn rldp_compatibility() {

    let (mut ctx_test, adnl, rldp) = init_rldp_compatibility_test("0.0.0.0:1");
    let mut ctx_search = None;
    let mut iter = None;
    let mut overlay_peers = Vec::new();

    loop {

        let (peer, ours) = find_rldp_peer(
            &adnl,
            &mut overlay_peers,  
            &mut ctx_search, 
            &mut iter,
            &mut ctx_test,
        );

        let rldp = rldp.clone();
        let ok = ctx_test.rt.block_on(
            async move {

                // Overlay ID
                let file_hash = base64_decode(ZEROSTATE_FILE_HASH).unwrap();
                let file_hash = file_hash.as_slice().try_into().unwrap();
                let overlay_id = OverlayUtils::calc_overlay_short_id(
                    -1, 
                    0x8000000000000000u64 as i64,
                    file_hash
                ).unwrap();
                let query = OverlayQuery {
                    overlay: UInt256::with_array(overlay_id.data().clone())
                };
                let query = serialize_boxed(&query).unwrap();

                // Zerostate
                if !download_by_block_id(
                    &rldp,
                    &peer,
                    &ours,
                    ZEROSTATE_ROOT_HASH,
                    ZEROSTATE_FILE_HASH,
                    0,
                    &query,
                    |block| (DownloadZeroState{ block }, "MC Zerostate".to_string())
                ).await {
                    return false
                }    

/*
                // Key block proof
                if !download_by_block_id(
                    &rldp,
                    &peer,
                    &ours,
                    "34qYxAeiFxFZzBSwXpcXqhd8RfKrdml7Z4HWXo98CU0=",
                    "aDLVLzppSkbkCtDaSiGjCGBZ/6Bd5YnCvR/TTtXLGDo=",
                    2343424,
                    &query,
                    |block| {
                        let title = format!("MC keyblock {} proof", block.seq_no);
                        (DownloadKeyBlockProof{ block }, title)
                    }
                ).await {
                    return false
                }    

                // Block
                if !download_by_block_id(
                    &rldp,
                    &peer,
                    &ours,
                    "sx8VBzPqUrd6PNsAvUvrm7YmMIRP4eYXLETuGWzTqvo=",
                    "av22mPrOMKJLH7OOu7wV8POxmDAIjXT7qBR/ZNguIxs=",
                    2331956,
                    &query,
                    |block| {
                        let title = format!("MC block {}", block.seq_no);
                        (DownloadKeyBlockProof{ block }, title)
                    }
                ).await {
                    return false
                }    
*/
                true

      	    }
        );

        if ok {
            break
        }

    }

    ctx_test.rt.block_on(
        async move {
            adnl.stop().await;
            ctx_test.adnl.stop().await;
        }
    )

}

#[test]
fn rldp_session() {
    let (rt, adnl1, rldp1, peer1, adnl2, rldp2, peer2) = init_local_test();
    rt.block_on(
        async move {
            let data_send = OverlayQuery {
                overlay: UInt256::with_array([0xAAu8; 32])
            };
            let data_send = serialize_boxed(&data_send).unwrap();
            let data_recv = build_reply();
            let peers = AdnlPeers::with_keys(peer1.clone(), peer2.clone());
            let max_answer_size = Some(513 * 1024);
            let data_send = TaggedByteSlice {
                object: data_send.as_slice(),
                #[cfg(feature = "telemetry")]
                tag: 0
            };
            assert_eq!(
                &rldp1.query(&data_send, max_answer_size, &peers, None).await.unwrap().0.unwrap(),
                &data_recv
            );
            let peers = AdnlPeers::with_keys(peer2.clone(), peer1.clone());
            assert_eq!(
                &rldp2.query(&data_send, max_answer_size, &peers, None).await.unwrap().0.unwrap(),
                &data_recv
            );
            adnl1.stop().await;
            adnl2.stop().await;
    	}
    )
}
