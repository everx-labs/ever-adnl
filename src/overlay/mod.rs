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
extern crate ton_api as ever_api;

use crate::{
    declare_counted,
    common::{
        add_counted_object_to_map, add_counted_object_to_map_with_update, 
        add_unbound_object_to_map, add_unbound_object_to_map_with_update, AdnlPeers, 
        CountedObject, Counter, hash, hash_boxed, Query, QueryAnswer, QueryResult, 
        Subscriber, TaggedByteSlice, TaggedTlObject, UpdatedAt, Version
    }, 
    node::{AddressCache, AdnlNode, DataCompression, IpAddress, PeerHistory}
};
#[cfg(feature = "telemetry")]
use crate::adnl::telemetry::Metric;
use crate::rldp::{Constraints, RaptorqDecoder, RaptorqEncoder, RldpNode};
use num_traits::pow::Pow;
use std::{
    convert::TryInto, sync::{Arc, atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering}},
    time::Duration
};
#[cfg(feature = "telemetry")]
use std::time::Instant;
use ever_api::{
    deserialize_boxed_bundle_with_suffix, IntoBoxed, serialize_boxed, serialize_boxed_append, 
    ton::{ //ever::{
        TLObject, adnl::id::short::Short as AdnlShortId, 
        catchain::{
            FirstBlock as CatchainFirstBlock, Update as CatchainBlockUpdateBoxed, 
            blockupdate::BlockUpdate as CatchainBlockUpdate
        },
        fec::{Type as FecType, type_::RaptorQ as FecTypeRaptorQ}, 
        overlay::{
            Broadcast, Certificate as OverlayCertificate, Message as OverlayMessageBoxed, 
            Nodes as NodesBoxed,
            broadcast::{
                Broadcast as BroadcastOrd, BroadcastFec, id::Id as BroadcastOrdId, 
                tosign::ToSign as BroadcastToSign
            },
            broadcast_fec::{id::Id as BroadcastFecId, partid::PartId as BroadcastFecPartId}, 
            message::Message as OverlayMessage, node::{Node, tosign::ToSign as NodeToSign},
            nodes::Nodes
        },
        pub_::publickey::{Ed25519, Overlay as OverlayKey}, 
        rpc::overlay::{GetRandomPeers, Query as OverlayQuery}, 
        ton_node::{ //ever_node::{
            BlockCandidateStatus, shardpublicoverlayid::ShardPublicOverlayId
        },
        validator_session::{
            BlockUpdate as ValidatorSessionBlockUpdateBoxed, 
            blockupdate::BlockUpdate as ValidatorSessionBlockUpdate
        }
    }
};
#[cfg(feature = "telemetry")]
use ever_api::{BoxedSerialize, tag_from_boxed_type, tag_from_bare_type};
use ever_block::{
    error, fail, 
    base64_decode, base64_encode, KeyId, KeyOption, Result, sha256_digest, UInt256
};

const TARGET: &str = "overlay";
const TARGET_BROADCAST: &str = "overlay_broadcast";

pub fn build_overlay_node_info(
    overlay: &Arc<OverlayShortId>,
    version: i32, 
    key: &str, 
    signature: &str
) -> Result<Node> {
    let key = base64_decode(key)?;
    if key.len() != 32 {
        fail!("Bad public key length")
    }
    let key: [u8; 32] = key.as_slice().try_into()?;
    let signature = base64_decode(signature)?;
    let node = Node {
        id: Ed25519 {
            key: UInt256::with_array(key)
        }.into_boxed(),
        overlay: UInt256::with_array(*overlay.data()),
        version,
        signature: signature.into()
    };
    Ok(node)
}

struct BroadcastReceiver<T> {
    data: lockfree::queue::Queue<Option<T>>,
    subscribers: lockfree::queue::Queue<Arc<tokio::sync::Barrier>>,
    synclock: AtomicU32,
    started_listening: AtomicBool,
}

impl <T: Send + 'static> BroadcastReceiver<T> {

    fn push(receiver: &Arc<Self>, data: T) {
        if receiver.started_listening.load(Ordering::Relaxed) {
            Self::do_push(receiver, Some(data))
        }
    }

    async fn pop(&self) -> Result<Option<T>> {
        self.started_listening.store(true, Ordering::Relaxed);
        self.synclock.fetch_add(1, Ordering::Relaxed);
        loop {
            if let Some(data) = self.data.pop() {
                self.synclock.fetch_sub(1, Ordering::Relaxed);
                return Ok(data)
            } else {
                let subscriber = Arc::new(tokio::sync::Barrier::new(2));
                self.subscribers.push(subscriber.clone());
                subscriber.wait().await;
            }
        }
    }

    fn stop(receiver: &Arc<Self>) {
        Self::do_push(receiver, None)
    }

    fn do_push(receiver: &Arc<Self>, data: Option<T>) {
        let receiver = receiver.clone();
        tokio::spawn(
            async move {
                receiver.data.push(data);
                while receiver.synclock.load(Ordering::Relaxed) > 0 {
                    if let Some(subscriber) = receiver.subscribers.pop() {
                        subscriber.wait().await;
                        break;
                    } else {
                        tokio::task::yield_now().await;
                    }
                }
            }
        );
    }

}

pub struct BroadcastRecvInfo {
    pub packets: u32,
    pub data: Vec<u8>,
    pub recv_from: Arc<KeyId>
}

#[derive(Debug, Default)]
pub struct BroadcastSendInfo {
    pub packets: u32,
    pub send_to: u32
}

pub type OverlayId = [u8; 32];
pub type OverlayShortId = KeyId;
pub type PrivateOverlayShortId = KeyId;

/// Overlay utilities
pub struct OverlayUtils;

impl OverlayUtils {

    /// Calculate overlay ID for public overlay
    pub fn calc_overlay_id(
        workchain: i32, 
        _shard: i64, 
        zero_state_file_hash: &[u8; 32]
    ) -> Result<OverlayId> {
        let overlay = ShardPublicOverlayId {
            shard: 1i64 << 63,
            workchain,
            zero_state_file_hash: UInt256::with_array(*zero_state_file_hash)
        };
        hash(overlay)
    }

    /// Calculate overlay short ID for public overlay
    pub fn calc_overlay_short_id(
        workchain: i32,
        shard: i64,
        zero_state_file_hash: &[u8; 32]
    ) -> Result<Arc<OverlayShortId>> {
        let overlay_key = OverlayKey {
            name: Self::calc_overlay_id(workchain, shard, zero_state_file_hash)?.to_vec().into()
        };
        Ok(OverlayShortId::from_data(hash(overlay_key)?))
    }

    /// Calculate overlay short ID for private overlay
    pub fn calc_private_overlay_short_id(
        first_block: &CatchainFirstBlock
    ) -> Result<Arc<PrivateOverlayShortId>> {
        let serialized_first_block = serialize_boxed(first_block)?;
        let overlay_key = OverlayKey { 
            name: serialized_first_block.into() 
        };
        let id = hash_boxed(&overlay_key.into_boxed())?;
        Ok(PrivateOverlayShortId::from_data(id))
    }

    /// Verify node info
    pub fn verify_node(overlay_id: &Arc<OverlayShortId>, node: &Node) -> Result<()> {
        let key: Arc<dyn KeyOption> = (&node.id).try_into()?;
        if node.overlay.as_slice() != overlay_id.data() {
            fail!(
                "Got peer {} with wrong overlay {}, expected {}",
                key.id(),
                base64_encode(node.overlay.as_slice()),
                overlay_id
            )
        }
        let node_to_sign = NodeToSign {
            id: AdnlShortId {
                id: UInt256::with_array(*key.id().data())
            },
            overlay: node.overlay.clone(),
            version: node.version 
        }.into_boxed();    
        if let Err(e) = key.verify(&serialize_boxed(&node_to_sign)?, &node.signature) {
            fail!("Got peer {} with bad signature: {}", key.id(), e)
        }
        Ok(())
    }

}

type BroadcastId = [u8; 32];
type CatchainReceiver = BroadcastReceiver<
    (CatchainBlockUpdate, ValidatorSessionBlockUpdate, Arc<KeyId>)
>;
type BlockCandidateStatusReceiver = BroadcastReceiver<
    (BlockCandidateStatus, Arc<KeyId>)
>;

enum OwnedBroadcast {
    Other,
    RecvFec(RecvTransferFec),
    WillBeRecvFec
}

#[cfg(feature = "telemetry")]
declare_counted!(
    struct TransferStats {
        income: AtomicU64,
        passed: AtomicU64,
        resent: AtomicU64
    }
);

#[cfg(feature = "telemetry")]
declare_counted!(
    struct PeerStats {
        count: AtomicU64
    }
);

declare_counted!(
    struct NodeObject {
        object: Node
    }
);

declare_counted!(
    struct Overlay {
        adnl: Arc<AdnlNode>,
        bad_peers: lockfree::set::Set<Arc<KeyId>>,
        flags: u8,
        hops: Option<u8>,
        known_peers: AddressCache,
        message_prefix: Vec<u8>,
        neighbours: AddressCache,
        nodes: lockfree::map::Map<Arc<KeyId>, NodeObject>,
        options: Arc<AtomicU32>,
        overlay_id: Arc<OverlayShortId>,
        overlay_key: Option<Arc<dyn KeyOption>>,
        owned_broadcasts: lockfree::map::Map<BroadcastId, OwnedBroadcast>,
        purge_broadcasts: lockfree::queue::Queue<BroadcastId>,
        purge_broadcasts_count: AtomicU32,
        query_prefix: Vec<u8>,
//        random_peers: AddressCache,
        received_catchain: Option<Arc<CatchainReceiver>>,
        received_block_status: Option<Arc<BlockCandidateStatusReceiver>>,
        received_peers: Arc<BroadcastReceiver<Vec<Node>>>,
        received_rawbytes: Arc<BroadcastReceiver<BroadcastRecvInfo>>,
        #[cfg(feature = "telemetry")]
        start: Instant,
        #[cfg(feature = "telemetry")]
        print: AtomicU64,
        #[cfg(feature = "telemetry")]
        messages_recv: AtomicU64,
        #[cfg(feature = "telemetry")]
        messages_send: AtomicU64,
        #[cfg(feature = "telemetry")]
        stats_per_peer_recv: lockfree::map::Map<Arc<KeyId>, lockfree::map::Map<u32, PeerStats>>,
        #[cfg(feature = "telemetry")]
        stats_per_peer_send: lockfree::map::Map<Arc<KeyId>, lockfree::map::Map<u32, PeerStats>>,
        #[cfg(feature = "telemetry")]
        stats_per_transfer: lockfree::map::Map<BroadcastId, TransferStats>,
        #[cfg(feature = "telemetry")]
        tag_broadcast_fec: u32,
        #[cfg(feature = "telemetry")]
        tag_broadcast_ord: u32,
        #[cfg(feature = "telemetry")]
        telemetry: Arc<OverlayTelemetry>,
        allocated: Arc<OverlayAlloc>,
        // For debug
        debug_trace: AtomicU32
   }
);

impl Overlay {

    const FLAG_BCAST_ANY_SENDER: i32 = 0x01;
    const FLAG_OVERLAY_OTHER_WORKCHAIN: u8 = 0x01;
    const MAX_HOPS: u8 = 15;
    const OPTION_DISABLE_BROADCAST_RETRANSMIT: u32 = 0x01;
    const SIZE_BROADCAST_WAVE: u32 = 20;
    const SIZE_NEIGHBOURS_LONG_BROADCAST: u8 = 5;
    const SIZE_NEIGHBOURS_SHORT_BROADCAST: u8 = 3;
    const SPINNER: u64 = 10;              // Milliseconds
    const TIMEOUT_BROADCAST: u64 = 60;    // Seconds

    fn calc_broadcast_id(&self, data: &[u8], allow_dup: bool) -> Result<Option<BroadcastId>> {
        let bcast_id = sha256_digest(data);
        let added = add_unbound_object_to_map_with_update(
            &self.owned_broadcasts, 
            bcast_id,
            |found| match found {
                None => Ok(Some(OwnedBroadcast::Other)),
                Some(OwnedBroadcast::Other) if allow_dup => Ok(Some(OwnedBroadcast::Other)),
                _ => Ok(None)
            }
        )?;
        if !added {
            Ok(None)
        } else {
            Ok(Some(bcast_id))
        }
    }

    fn calc_broadcast_to_sign(data: &[u8], date: i32, src: [u8; 32]) -> Result<Vec<u8>> { 
        let data_hash = sha256_digest(data);
        let bcast_id = BroadcastOrdId {
            src: UInt256::with_array(src),
            data_hash: UInt256::with_array(data_hash),
            flags: Self::FLAG_BCAST_ANY_SENDER
        };
        let data_hash = hash(bcast_id)?;
        let to_sign = BroadcastToSign {
            hash: UInt256::with_array(data_hash),
            date
        }.into_boxed();
        serialize_boxed(&to_sign)
    }

    #[allow(clippy::too_many_arguments)]
    fn calc_fec_part_to_sign(
        data_hash: &[u8; 32],
        data_size: i32, 
        date: i32, 
        flags: i32,
        params: &FecTypeRaptorQ,
        part: &[u8],
        seqno: i32,
        src: [u8; 32]
    ) -> Result<Vec<u8>> {

        let broadcast_id = BroadcastFecId {
            src: UInt256::with_array(src),
            type_: UInt256::with_array(hash(params.clone())?),
            data_hash: UInt256::with_array(*data_hash),
            size: data_size,
            flags
        };
        let broadcast_hash = hash(broadcast_id)?;
        let part_data_hash: [u8; 32] = sha256_digest(part);

        let part_id = BroadcastFecPartId {
            broadcast_hash: UInt256::with_array(broadcast_hash),
            data_hash: UInt256::with_array(part_data_hash),
            seqno
        };
        let part_hash = hash(part_id)?;

        let to_sign = BroadcastToSign {
            hash: UInt256::with_array(part_hash),
            date
        }.into_boxed();
        serialize_boxed(&to_sign)

    }

    fn calc_broadcast_neighbours(
        &self, 
        hops: Option<u8>,
        default_neighbours: u8,
        skip: Option<&Arc<KeyId>>
    ) -> Result<(Option<u8>, Vec<Arc<KeyId>>)> { 
        let (hops, neighbours) = if let Some(mut hops) = hops {
            let initial = (hops >> 4) == 0;
            if initial {
                hops |= hops << 4;
            }
            let hops_org = hops >> 4;
            let hops_cur = hops & 0x0F;
            if hops_org > Self::MAX_HOPS {
                fail!("Too big hops count requested ({})", hops_org)
            }
            if (hops_cur > hops_org) || (hops_cur <= 1) {
                fail!("Bad hops counter ({:x})", hops)
            }
            // Heuristics with zero loss, where n is the number of nodes in network
            // M3(n) = 3.42 * n^0.287 
            // M4(n) = 3.86 * n^0.181
            let n = self.known_peers.count() as f64;
            let n = if hops_org <= 3 {
                (n.pow(0.287f64) * 3.42f64).ceil() as u8 
            } else {
                (n.pow(0.181f64) * 3.86f64).ceil() as u8
            };
            if n > self.neighbours.count() as u8 {
                if initial {
                    if hops_org < Self::MAX_HOPS {
                        hops = ((hops_org + 1) << 4) | (hops_org + 1)
                    }
                    (Some(hops), default_neighbours)
                } else {
                    (None, default_neighbours)                         
                }
            } else {
                if !initial {
                    hops -= 1;
                }
                (Some(hops), n)
            }
        } else {
            (None, default_neighbours)
        };
        let neighbours = self.neighbours.random_vec(skip, neighbours as u32);
        Ok((hops, neighbours))
    }

    fn create_fec_recv_transfer(
        overlay: &Arc<Self>, 
        bcast: &BroadcastFec
    ) -> Result<RecvTransferFec> {
                                                                                                         
        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = &bcast.fec {
            fec_type
        } else {
            fail!("Unsupported FEC type")
        };

        let overlay_recv = overlay.clone();
        let bcast_id_recv = bcast.data_hash.as_array().clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();
        let mut decoder = RaptorqDecoder::with_params(fec_type.clone());
        let overlay_wait = overlay_recv.clone();
        let bcast_id_wait = bcast_id_recv;
        let source: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        let source = source.id().clone();
        let source_recv = source.clone();
        let bcast_data_size = bcast.data_size;

        tokio::spawn(
            async move {
                let mut received = false;
                let mut packets = 0;
                #[cfg(feature = "telemetry")]
                let mut flags = RecvTransferFecTelemetry::FLAG_RECEIVE_STARTED;
                #[cfg(feature = "telemetry")]
                let mut len = 0;
                #[cfg(feature = "telemetry")]
                let mut tag = 0;
                while let Some(bcast) = reader.recv().await {
                    let bcast = match bcast {
                        Some(bcast) => bcast,
                        None => break
                    };
                    packets += 1; 
                    match Self::process_fec_broadcast(&overlay_recv, &mut decoder, &bcast) {
                        Err(err) => {
                            log::warn!(
                                target: TARGET, 
                                "Error when receiving overlay {} broadcast: {}",
                                overlay_recv.overlay_id,
                                err
                            );
                            #[cfg(feature = "telemetry")] {
                                flags |= RecvTransferFecTelemetry::FLAG_FAILED;
                            }
                        },
                        Ok(Some(data)) => {
                            #[cfg(feature = "telemetry")] {
                                if data.len() > 4 {
                                    tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                                }
                                len = data.len() as u32;
                                flags |= RecvTransferFecTelemetry::FLAG_RECEIVED;
                            }
                            BroadcastReceiver::push(
                                &overlay_recv.received_rawbytes,
                                BroadcastRecvInfo {
                                    packets,
                                    data,
                                    recv_from: source_recv
                                }
                            );
                            received = true
                        },
                        Ok(None) => continue
                    } 
                    break;
                }   
                if received {
                    if let Some(transfer) = overlay_recv.owned_broadcasts.get(
                        &bcast_id_recv
                    ) {
                        if let OwnedBroadcast::RecvFec(transfer) = transfer.val() {
                            transfer.completed.store(true, Ordering::Relaxed);
                            #[cfg(feature = "telemetry")] {
                                transfer.telemetry.flags.fetch_or(flags, Ordering::Relaxed);
                                transfer.telemetry.len.store(len, Ordering::Relaxed);
                                transfer.telemetry.tag.store(tag, Ordering::Relaxed);
                            }
                        } else {
                            log::error!(  
                                target: TARGET, 
                                "INTERNAL ERROR: recv FEC broadcast {} mismatch in overlay {}",
                                base64_encode(&bcast_id_recv),
                                overlay_recv.overlay_id
                            )
                        }
                    }
                }
                // Graceful close
                reader.close();
                while reader.recv().await.is_some() { 
                }
            }
        );

        tokio::spawn(
            async move {
                loop {
                    tokio::time::sleep(
                        Duration::from_millis(Self::TIMEOUT_BROADCAST * 100)
                    ).await;
                    if let Some(transfer) = overlay_wait.owned_broadcasts.get(
                        &bcast_id_wait
                    ) {
                        if let OwnedBroadcast::RecvFec(transfer) = transfer.val() {
                            if !transfer.updated_at.is_expired(Self::TIMEOUT_BROADCAST) {
                                continue
                            }
                            if !transfer.completed.load(Ordering::Relaxed) {
                                log::warn!(  
                                    target: TARGET, 
                                    "FEC broadcast {} ({} bytes) dropped incompleted by timeout",
                                    base64_encode(&bcast_id_wait),
                                    bcast_data_size
                                )
                            }
                            // Abort receiving loop
                            transfer.sender.send(None).ok();
                        } else {
                            log::error!(  
                                target: TARGET, 
                                "INTERNAL ERROR: recv FEC broadcast {} mismatch in overlay {}",
                                base64_encode(&bcast_id_wait),
                                overlay_wait.overlay_id
                            )
                        }
                    }
                    break
                }
                Self::setup_broadcast_purge(&overlay_wait, bcast_id_wait);
            }
        );

        let ret = RecvTransferFec {
            completed: AtomicBool::new(false),
            history: PeerHistory::for_recv(),
            sender,
            source,
            #[cfg(feature = "telemetry")]
            telemetry: RecvTransferFecTelemetry {
                flags: AtomicU32::new(0),
                len: AtomicU32::new(0),
                tag: AtomicU32::new(0)
            },
            updated_at: UpdatedAt::new(),
            counter: overlay.allocated.recv_transfers.clone().into()
        };
        #[cfg(feature = "telemetry")]
        overlay.telemetry.recv_transfers.update(
            overlay.allocated.recv_transfers.load(Ordering::Relaxed)
        );  
        Ok(ret)

    }

    fn create_fec_send_transfer(
        overlay: &Arc<Self>, 
        data: &TaggedByteSlice, 
        source: &Arc<dyn KeyOption>,
        overlay_key: &Arc<KeyId>,
        allow_dup: bool
    ) -> Result<BroadcastSendInfo> {

        let overlay_clone = overlay.clone();
        let source = source.clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();

        let bcast_id = if let Some(bcast_id) = overlay.calc_broadcast_id(data.object, allow_dup)? {
            bcast_id
        } else {
            log::warn!(target: TARGET, "Trying to send duplicated broadcast");
            return Ok(BroadcastSendInfo::default())
        };

        #[cfg(feature = "telemetry")]
        let tag = data.tag;
        let data = if overlay.adnl.check_options(AdnlNode::OPTION_FORCE_COMPRESSION) {
            DataCompression::compress(data.object)?
        } else {
            data.object.to_vec()
        };
        let data_size = data.len() as u32;

        let mut transfer = SendTransferFec {
            bcast_id,
            encoder: RaptorqEncoder::with_data(&data),
            seqno: 0,
            counter: overlay.allocated.send_transfers.clone().into()
        };
        #[cfg(feature = "telemetry")]
        overlay.telemetry.send_transfers.update(
            overlay.allocated.send_transfers.load(Ordering::Relaxed)
        );
        let max_seqno = (data_size / transfer.encoder.params().symbol_size as u32 + 1) * 3 / 2;

        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: send FEC {} {} bytes, tag {:08x} to overlay {}",
            base64_encode(&bcast_id),  
            data.len(),
            tag,
            overlay.overlay_id
        );

        tokio::spawn(
            async move {
                while transfer.seqno <= max_seqno {
                    for _ in 0..Self::SIZE_BROADCAST_WAVE {
                        let result = overlay_clone
                            .prepare_fec_broadcast(&mut transfer, &source)
                            .and_then(
                                |data| {
                                    sender.send(data)?; 
                                    Ok(())
                                }
                            );
                        if let Err(err) = result {
                            log::warn!(
                                target: TARGET, 
                                "Error when sending overlay {} broadcast: {}",
                                overlay_clone.overlay_id,
                                err
                            );
                            return
                        }
                        if transfer.seqno > max_seqno {
                            break
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(Self::SPINNER)).await;            
                }
            }
        );

        let overlay = overlay.clone();
        let overlay_key = overlay_key.clone();
        let (hops, neighbours) = overlay.calc_broadcast_neighbours(
            overlay.hops,  
            Self::SIZE_NEIGHBOURS_LONG_BROADCAST, 
            None
        )?;
        let ret = BroadcastSendInfo {
            packets: max_seqno,
            send_to: neighbours.len() as u32
        };

        tokio::spawn(
            async move {
                while let Some(mut buf) = reader.recv().await {
                    if let Some(hops) = &hops {
                        buf.push(*hops)
                    }
                    if let Err(err) = overlay.distribute_broadcast(
                        &TaggedByteSlice {
                            object: &buf, 
                            #[cfg(feature = "telemetry")]
                            tag
                        },
                        &overlay_key,
                        &neighbours, 
                    ).await {
                        log::warn!(
                            target: TARGET, 
                            "Error when sending overlay {} FEC broadcast: {}",
                            overlay.overlay_id,
                            err
                        );
                    }
                }
                // Graceful close
                reader.close();
                while reader.recv().await.is_some() { 
                }
                Self::setup_broadcast_purge(&overlay, bcast_id);
            }
        );
        Ok(ret)
        
    }

    async fn distribute_broadcast(
        &self, 
        data: &TaggedByteSlice<'_>,
        key: &Arc<KeyId>,
        neighbours: &[Arc<KeyId>]
    ) -> Result<()> {
        log::trace!(
            target: TARGET,
            "Broadcast {} bytes to overlay {}, {} neighbours",
            data.object.len(),
            self.overlay_id,
            neighbours.len()
        );
        let mut peers: Option<AdnlPeers> = None;
        #[cfg(feature = "telemetry")]
        let mut addrs = Vec::new();
        for neighbour in neighbours.iter() {
            #[cfg(feature = "telemetry")]
            if let Err(e) = self.update_stats(neighbour, data.tag, true) {
                log::warn!(
                    target: TARGET,
                    "Cannot update statistics in overlay {} for {} during broadcast: {}",
                    self.overlay_id, neighbour, e
                )
            }
            let peers = if let Some(peers) = &mut peers {
                peers.set_other(neighbour.clone());
                peers
            } else {
                peers.get_or_insert_with(|| AdnlPeers::with_keys(key.clone(), neighbour.clone()))
            };
            #[cfg(feature = "telemetry")]
            addrs.push(peers.other().to_string());
            if let Err(e) = self.adnl.send_custom(data, peers) {
                log::warn!(
                    target: TARGET,
                    "Cannot distribute broadcast in overlay {} to {}: {}",
                    self.overlay_id, neighbour, e
                )
            }
        }
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: distributed {} bytes to overlay {}, peers {:?}",
            data.object.len(),
            self.overlay_id,
            addrs
        );
        Ok(())
    }

    fn is_broadcast_outdated(&self, date: i32, peer: &Arc<KeyId>) -> bool {
        let now = Version::get();
        if date + (Self::TIMEOUT_BROADCAST as i32) < now {
            log::warn!(
                target: TARGET,
                "Old FEC broadcast {} seconds old from {} in overlay {}",
                now - date,
                peer,
                self.overlay_id
            );
            true
        } else {
            false
        }
    }

    fn prepare_fec_broadcast(
        &self, 
        transfer: &mut SendTransferFec, 
        key: &Arc<dyn KeyOption>
    ) -> Result<Vec<u8>> {

        let chunk = transfer.encoder.encode(&mut transfer.seqno)?;
        let date = Version::get();
        let signature = Self::calc_fec_part_to_sign(
            &transfer.bcast_id,
            transfer.encoder.params().data_size, 
            date, 
            Self::FLAG_BCAST_ANY_SENDER,
            transfer.encoder.params(),
            &chunk,
            transfer.seqno as i32,
            [0u8; 32]
        )?;
        let signature = key.sign(&signature)?;

        let bcast = BroadcastFec {
            src: key.try_into()?,
            certificate: OverlayCertificate::Overlay_EmptyCertificate,
            data_hash: UInt256::with_array(transfer.bcast_id),
            data_size: transfer.encoder.params().data_size, 
            flags: Self::FLAG_BCAST_ANY_SENDER,
            data: chunk.into(),
            seqno: transfer.seqno as i32, 
            fec: transfer.encoder.params().clone().into_boxed(),
            date,
            signature: signature.into()
        }.into_boxed();

        transfer.seqno += 1;
        let mut buf = self.message_prefix.clone();
        serialize_boxed_append(&mut buf, &bcast)?;
        Ok(buf)
    }

    fn process_fec_broadcast(
        overlay: &Arc<Overlay>, 
        decoder: &mut RaptorqDecoder,
        bcast: &BroadcastFec
    ) -> Result<Option<Vec<u8>>> {

        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = &bcast.fec {
            fec_type
        } else {
            fail!("Unsupported FEC type")
        };

        let src_key: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        let src = if (bcast.flags & Self::FLAG_BCAST_ANY_SENDER) != 0 {
            [0u8; 32]
        } else {
            *src_key.id().data()
        };

        let bcast_id = bcast.data_hash.as_slice();
        let signature = Self::calc_fec_part_to_sign(
            bcast_id,
            bcast.data_size, 
            bcast.date,
            bcast.flags,
            fec_type,
            &bcast.data,
            bcast.seqno,
            src
        )?;
        src_key.verify(&signature, &bcast.signature)?;

        if let Some(ret) = decoder.decode(bcast.seqno as u32, &bcast.data) {
            let ret = if ret.len() != bcast.data_size as usize {
                fail!("Expected {} bytes, but received {}", bcast.data_size, ret.len())
            } else {
                let (ret, check) = match DataCompression::decompress(&ret[..]) {
                    Some(maybe) => if sha256_digest(&maybe) != *bcast_id {
                        (ret, true)
                    } else {
                        overlay.adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION); 
                        (maybe, false)
                    },
                    None => (ret, true)
                };
                if check {
                    let test_id = sha256_digest(&ret);
                    if test_id != *bcast_id {
                        fail!(
                            "Expected {} broadcast hash, but received {}",
                            base64_encode(test_id), 
                            base64_encode(bcast_id)
                        )
                    }
                }
                let delay = Version::get() - bcast.date;
                if delay > 1 {
                    log::warn!(
                        target: TARGET,
                        "Received overlay broadcast {} ({} bytes) in {} seconds",
                        base64_encode(bcast_id),
                        ret.len(),
                        delay
                    )
                } else {
                    log::trace!(
                        target: TARGET,
                        "Received overlay broadcast {} ({} bytes) in {} seconds",
                        base64_encode(bcast_id), 
                        ret.len(),
                        delay
                    )
                }
                ret
            };
            Ok(Some(ret))
        } else {
            Ok(None)
        }
        
    }

    async fn receive_broadcast(
        overlay: &Arc<Self>, 
        bcast: BroadcastOrd,
        raw_data: &[u8],
        check_hops: bool,
        peers: &AdnlPeers
    ) -> Result<()> {
        if overlay.is_broadcast_outdated(bcast.date, peers.other()) {
            return Ok(())
        }
        let src_key: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        let src = if (bcast.flags & Self::FLAG_BCAST_ANY_SENDER) != 0 {
            [0u8; 32]
        } else {
            *src_key.id().data()
        };
        let data: Vec<u8> = bcast.data.into();
        let (data, mut bcast_id, check) = match DataCompression::decompress(&data) {
            Some(maybe) => {
                let signature = Self::calc_broadcast_to_sign(&maybe, bcast.date, src)?;
                match overlay.calc_broadcast_id(&signature, false)? {
                    Some(bcast_id) => match src_key.verify(&signature, &bcast.signature) {
                        Ok(_) => {
                            overlay.adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
                            (maybe, Some(bcast_id), false)
                        },
                        Err(_) => (data, None, true)
                    },
                    None => (maybe, None, false)
                }
            },
            None => (data, None, true)
        };
        if check {
            let signature = Self::calc_broadcast_to_sign(&data[..], bcast.date, src)?;
            bcast_id = overlay.calc_broadcast_id(&signature, false)?;
            if bcast_id.is_some() {
                src_key.verify(&signature, &bcast.signature)?
            }
        }
        let bcast_id = match bcast_id {
            Some(bcast_id) => bcast_id,
            None => return Ok(())
        };
        log::trace!(target: TARGET, "Received overlay broadcast, {} bytes", data.len());
        #[cfg(feature = "telemetry")]
        let tag = if data.len() >= 4 {
            let tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            log::info!(
                target: TARGET_BROADCAST,
                "Broadcast trace: recv ordinary {} {} bytes, tag {:08x} to overlay {}",
                base64_encode(&bcast_id),  
                data.len(),
                tag,
                overlay.overlay_id
            );
            tag
        } else {
            overlay.tag_broadcast_ord
        };
        BroadcastReceiver::push(
            &overlay.received_rawbytes,
            BroadcastRecvInfo {
                packets: 1,
                data,
                recv_from: src_key.id().clone()
            }
        );
        overlay.resend_broadcast(
            raw_data,
            check_hops,
            peers,
            Self::SIZE_NEIGHBOURS_SHORT_BROADCAST, 
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(feature = "telemetry")]
            tag
        ).await?;
        Self::setup_broadcast_purge(overlay, bcast_id);
        Ok(())
    }

    async fn receive_fec_broadcast(
        overlay: &Arc<Self>, 
        bcast: BroadcastFec,
        raw_data: &[u8],
        check_hops: bool,
        peers: &AdnlPeers 
    ) -> Result<()> {
        if overlay.is_broadcast_outdated(bcast.date, peers.other()) {
            return Ok(())
        }
        let bcast_id = bcast.data_hash.as_slice();
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: recv FEC {} {} bytes to overlay {}",
            base64_encode(bcast_id),  
            raw_data.len(),
            overlay.overlay_id
        );
        #[cfg(feature = "telemetry")]
        let stats = if let Some(stats) = overlay.stats_per_transfer.get(bcast_id) {
            stats
        } else {
            add_counted_object_to_map(
                &overlay.stats_per_transfer,
                bcast_id.clone(),
                || {
                    let ret = TransferStats {
                        income: AtomicU64::new(0),
                        passed: AtomicU64::new(0),
                        resent: AtomicU64::new(0),
                        counter: overlay.allocated.stats_transfer.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    overlay.telemetry.stats_transfer.update(
                        overlay.allocated.stats_transfer.load(Ordering::Relaxed)
                    );
                    Ok(ret)
                }
            )?;
            overlay.stats_per_transfer.get(bcast_id).ok_or_else(
                || error!("INTERNAL ERROR: Cannot count transfer statistics")
            )?
        };
        #[cfg(feature = "telemetry")]
        stats.val().income.fetch_add(1, Ordering::Relaxed);
        let transfer = loop {
            if let Some(transfer) = overlay.owned_broadcasts.get(bcast_id) {
                break transfer
            }
            if !add_unbound_object_to_map(
                &overlay.owned_broadcasts, 
                *bcast_id,
                || Ok(OwnedBroadcast::WillBeRecvFec)
            )? {
                tokio::task::yield_now().await;
                continue;
            }
            let transfer = Self::create_fec_recv_transfer(overlay, &bcast);
            if transfer.is_err() {
                overlay.owned_broadcasts.remove(bcast_id);
            }
            let transfer = OwnedBroadcast::RecvFec(transfer?);
            let ok = match overlay.owned_broadcasts.insert(*bcast_id, transfer) {
                Some(removed) => matches!(removed.val(), OwnedBroadcast::WillBeRecvFec),
                _ => false
            };
            if !ok {
                log::error!(  
                    target: TARGET, 
                    "INTERNAL ERROR: recv FEC broadcast {} creation mismatch in overlay {}",
                    base64_encode(bcast_id),
                    overlay.overlay_id
                )
            }
        };
        let transfer = transfer.val();
        let transfer = if let OwnedBroadcast::RecvFec(transfer) = transfer {
            transfer
        } else {
            // Not a receive FEC broadcast 
            return Ok(())
        };
        transfer.updated_at.refresh();
        let src_key: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        if &transfer.source != src_key.id() {
            log::warn!(
                target: TARGET, 
                "Same broadcast {} but parts from different sources",
                base64_encode(bcast_id)
            );
            return Ok(())
        }
        if !transfer.history.update(bcast.seqno as u64, TARGET_BROADCAST).await? {
            return Ok(())
        }
        #[cfg(feature = "telemetry")]
        stats.val().passed.fetch_add(1, Ordering::Relaxed);
        if !transfer.completed.load(Ordering::Relaxed) {
            transfer.sender.send(Some(bcast))?;
        }
        overlay.resend_broadcast(
            raw_data,
            check_hops,
            peers,
            Self::SIZE_NEIGHBOURS_LONG_BROADCAST, 
            #[cfg(feature = "telemetry")]
            Some(stats.val()),
            #[cfg(feature = "telemetry")]
            overlay.tag_broadcast_fec
        ).await
    }

    async fn resend_broadcast(
        &self, 
        raw_data: &[u8],
        check_hops: bool,
        peers: &AdnlPeers,
        neighbours: u8, 
        #[cfg(feature = "telemetry")]
        stats: Option<&TransferStats>,
        #[cfg(feature = "telemetry")]
        tag: u32
    ) -> Result<()> {
        let options = self.options.load(Ordering::Relaxed);
        if (options & Overlay::OPTION_DISABLE_BROADCAST_RETRANSMIT) != 0 {
            return Ok(())                                                                              
        }
        let hops = if check_hops {
            if raw_data.is_empty() {
                fail!("Empty broadcast data with hops check")
            }
            let hops = raw_data[raw_data.len() - 1]; 
            if (hops & 0x0F) <= 1 {
                return Ok(())
            }
            Some(hops)
        } else {
            self.hops
        };                          
        let (hops, neighbours) = self.calc_broadcast_neighbours(
            hops, 
            neighbours, 
            Some(peers.other())
        )?;
        #[cfg(feature = "telemetry")]
        if let Some(stats) = stats {
            stats.resent.fetch_add(neighbours.len() as u64, Ordering::Relaxed);
        }
        // Transit broadcasts will be traced untagged 
        if let Some(hops) = hops {
            let len = raw_data.len();
            let mut buf = Vec::with_capacity(len);
            buf.extend_from_slice(raw_data);
            buf[len - 1] = hops;
            self.distribute_broadcast(
                &TaggedByteSlice {
                    object: &buf,
                    #[cfg(feature = "telemetry")]
                    tag
                },
                peers.local(),
                &neighbours,
            ).await
        } else {
            self.distribute_broadcast(
                &TaggedByteSlice {
                    object: raw_data, 
                    #[cfg(feature = "telemetry")]
                    tag
                },
                peers.local(),
                &neighbours,
            ).await
        }
    }

    async fn send_broadcast(
        overlay: &Arc<Self>, 
        data: &TaggedByteSlice<'_>, 
        source: &Arc<dyn KeyOption>,
        overlay_key: &Arc<KeyId>,
        allow_dup: bool
    ) -> Result<BroadcastSendInfo> {
        let date = Version::get();
        let signature = Self::calc_broadcast_to_sign(data.object, date, [0u8; 32])?;
        let bcast_id = if let Some(bcast_id) = overlay.calc_broadcast_id(&signature, allow_dup)? {
            bcast_id
        } else {
            log::warn!(target: TARGET, "Trying to send duplicated broadcast");
            return Ok(BroadcastSendInfo::default())
        };
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: send ordinary {} {} bytes, tag {:08x} to overlay {}",
            base64_encode(&bcast_id),  
            data.object.len(),
            data.tag,
            overlay.overlay_id
        );
        let data_body = if overlay.adnl.check_options(AdnlNode::OPTION_FORCE_COMPRESSION) {
            DataCompression::compress(data.object)?
        } else {
            data.object.to_vec()
        };
        let signature = source.sign(&signature)?;
        let bcast = BroadcastOrd {
            src: source.try_into()?,
            certificate: OverlayCertificate::Overlay_EmptyCertificate,
            flags: Self::FLAG_BCAST_ANY_SENDER,
            data: data_body.into(),
            date,
            signature: signature.into()
        }.into_boxed();
        let mut buf = overlay.message_prefix.clone();
        serialize_boxed_append(&mut buf, &bcast)?;
        let (hops, neighbours) = overlay.calc_broadcast_neighbours(
            overlay.hops,
            Self::SIZE_NEIGHBOURS_SHORT_BROADCAST,
            None
        )?;
        if let Some(hops) = hops {  
            buf.push(hops);
        }
        overlay.distribute_broadcast(
            &TaggedByteSlice {
                object: &buf, 
                #[cfg(feature = "telemetry")]
                tag: data.tag
            },
            overlay_key,
            &neighbours,
        ).await?;
        Self::setup_broadcast_purge(overlay, bcast_id);
        let ret = BroadcastSendInfo {
            packets: 1,
            send_to: neighbours.len() as u32
        };
        Ok(ret)
    } 

    fn setup_broadcast_purge(overlay: &Arc<Self>, bcast_id: BroadcastId) {
        let overlay = overlay.clone();
        tokio::spawn(
            async move {
                tokio::time::sleep(Duration::from_secs(Self::TIMEOUT_BROADCAST)).await;
                overlay.purge_broadcasts_count.fetch_add(1, Ordering::Relaxed);
                overlay.purge_broadcasts.push(bcast_id);
            }
        );
    }

    fn update_neighbours(&self, n: u32) -> Result<()> {
        if self.overlay_key.is_some() {
            self.known_peers.random_set(&self.neighbours, None, n)
        } else {
            self.known_peers.random_set(&self.neighbours, Some(&self.bad_peers), n)
//            self.random_peers.random_set(&self.neighbours, Some(&self.bad_peers), n)
        }
    }

//    fn update_random_peers(&self, n: u32) -> Result<()> {
//        self.known_peers.random_set(&self.random_peers, Some(&self.bad_peers), n)?;
//        self.update_neighbours(OverlayNode::MAX_OVERLAY_NEIGHBOURS)
//    }

    #[cfg(feature = "telemetry")]
    fn print_stats(&self) -> Result<()> {
        let elapsed = self.start.elapsed().as_secs();
        if elapsed == 0 {
            // Too early to print stats
            return Ok(())
        }
        let messages_recv = self.messages_recv.load(Ordering::Relaxed);
        let messages_send = self.messages_send.load(Ordering::Relaxed);
        log::info!(
            target: TARGET,
            "------- OVERLAY STAT send {}: {} messages, {} messages/sec average load",
            self.overlay_id, messages_send, messages_send / elapsed
        );
        for dst in self.stats_per_peer_send.iter() {
            log::info!(
                target: TARGET, 
                "  -- OVERLAY STAT send {} to {}", 
                self.overlay_id, dst.key()
            );
            for tag in dst.val().iter() {
                let count = tag.val().count.load(Ordering::Relaxed);
                if count / elapsed < 1 {
                    continue
                }
                log::info!(
                    target: TARGET, 
                    "  OVERLAY STAT send {} tag {:x}: {}, {} per sec average load", 
                    self.overlay_id, tag.key(), count, count / elapsed
                );
            }
        }
        log::info!(
            target: TARGET,
            "------- OVERLAY STAT recv {}: {} messages, {} messages/sec average load",
            self.overlay_id, messages_recv, messages_recv / elapsed
        );
        for dst in self.stats_per_peer_recv.iter() {
            log::info!(
                target: TARGET, 
                "  -- OVERLAY STAT recv {} from {}", 
                self.overlay_id, dst.key()
            );
            for tag in dst.val().iter() {
                let count = tag.val().count.load(Ordering::Relaxed);
                if count / elapsed < 1 {
                    continue;
                }
                log::info!(
                    target: TARGET, 
                    "  OVERLAY STAT recv {} tag {:x}: {}, {} per sec average load", 
                    self.overlay_id, tag.key(), count, count / elapsed
                );
            }
        }
        let mut inc = 0;
        let mut pas = 0;
        let mut res = 0;
        for transfer in self.stats_per_transfer.iter() {
            inc += transfer.val().income.load(Ordering::Relaxed);
            pas += transfer.val().passed.load(Ordering::Relaxed);
            res += transfer.val().resent.load(Ordering::Relaxed);
/*
            log::info!(
                target: TARGET, 
                "  ** OVERLAY STAT resend transfer {}: -> {} / {} -> {}", 
                base64_encode(transfer.key()), 
                transfer.val().income.load(Ordering::Relaxed),
                transfer.val().passed.load(Ordering::Relaxed),
                transfer.val().resent.load(Ordering::Relaxed)
            )
*/
        }
        log::info!(
            target: TARGET, 
            "  ** OVERLAY STAT resend {} / {} -> {}", 
            inc, pas, res
        );
        let map = lockfree::map::Map::new();
        for transfer in self.owned_broadcasts.iter() {
            if let OwnedBroadcast::RecvFec(transfer) = transfer.val() {
                if transfer.updated_at.is_expired(5) {
                    continue
                }
                let mut tag = transfer.telemetry.tag.load(Ordering::Relaxed);
                let flags = transfer.telemetry.flags.load(Ordering::Relaxed);
                if (flags & RecvTransferFecTelemetry::FLAG_RECEIVED) == 0 {
                    tag |= flags;
                }
                add_unbound_object_to_map(
                    &map,
                    tag,
                    || Ok((AtomicU32::new(0), AtomicU32::new(0)))
                )?;
                if let Some(item) = map.get(&tag) {
                   let (cnt, len) = item.val();
                   cnt.fetch_add(1, Ordering::Relaxed);
                   len.fetch_add(
                       transfer.telemetry.len.load(Ordering::Relaxed), 
                       Ordering::Relaxed
                   );
                }
            }
        }
        for item in map.iter() {
            let (cnt, len) = item.val();
            let cnt = cnt.load(Ordering::Relaxed);
            let len = len.load(Ordering::Relaxed) / cnt;
            log::info!(
                target: TARGET, 
                "  ** OVERLAY STAT resend by tag {:x}: {}, {} bytes avg", 
                item.key(), cnt, len
            )
        }
        Ok(())
    }

    #[cfg(feature = "telemetry")]
    fn update_stats(&self, dst: &Arc<KeyId>, tag: u32, is_send: bool) -> Result<()> {
        let stats = if is_send {
            &self.stats_per_peer_send
        } else {
            &self.stats_per_peer_recv
        };
        let stats = if let Some(stats) = stats.get(dst) {
            stats 
        } else {
            add_unbound_object_to_map(
                stats,
                dst.clone(),
                || Ok(lockfree::map::Map::new())
            )?;
            if let Some(stats) = stats.get(dst) {
                stats
            } else {
                fail!(
                    "INTERNAL ERROR: cannot add overlay statistics for {}:{}", 
                    self.overlay_id, dst
                )
            }
        };
        let stats = if let Some(stats) = stats.val().get(&tag) {
            stats
        } else {
            add_counted_object_to_map(
                stats.val(),
                tag,
                || {
                    let ret = PeerStats {
                        count: AtomicU64::new(0),
                        counter: self.allocated.stats_peer.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    self.telemetry.stats_peer.update(
                        self.allocated.stats_peer.load(Ordering::Relaxed)
                    );
                    Ok(ret)
                }
            )?;
            if let Some(stats) = stats.val().get(&tag) {
                stats
            } else {
                fail!(
                    "INTERNAL ERROR: cannot add overlay statistics for {}:{}:{}", 
                    self.overlay_id, dst, tag
                )
            }
        };
        stats.val().count.fetch_add(1, Ordering::Relaxed);
        if is_send {
            self.messages_send.fetch_add(1, Ordering::Relaxed);
        } else {
            self.messages_recv.fetch_add(1, Ordering::Relaxed);
        }
        let elapsed = self.start.elapsed().as_secs();
        if elapsed > self.print.load(Ordering::Relaxed) {
            self.print.store(elapsed + 5, Ordering::Relaxed);
            self.print_stats()?;
        }
        Ok(())
    }

}

#[cfg(feature = "telemetry")]
struct RecvTransferFecTelemetry {
    flags: AtomicU32,
    len: AtomicU32, 
    tag: AtomicU32 
}

#[cfg(feature = "telemetry")]
impl RecvTransferFecTelemetry {
    const FLAG_RECEIVE_STARTED: u32 = 0x01;
    const FLAG_RECEIVED: u32        = 0x02;
    const FLAG_FAILED: u32          = 0x04;
}

declare_counted!(
    struct RecvTransferFec {
        completed: AtomicBool,
        history: PeerHistory,
        sender: tokio::sync::mpsc::UnboundedSender<Option<BroadcastFec>>,
        source: Arc<KeyId>,
        #[cfg(feature = "telemetry")]
        telemetry: RecvTransferFecTelemetry,
        updated_at: UpdatedAt
    }
);

declare_counted!(
    struct SendTransferFec {
        bcast_id: BroadcastId,
        encoder: RaptorqEncoder,
        seqno: u32
    }
);

declare_counted!(
    struct ConsumerObject {
        object: Arc<dyn Subscriber>
    }
);

struct OverlayAlloc {
    consumers: Arc<AtomicU64>,
    overlays: Arc<AtomicU64>,
    peers: Arc<AtomicU64>,
    recv_transfers: Arc<AtomicU64>,
    send_transfers: Arc<AtomicU64>,
    #[cfg(feature = "telemetry")]
    stats_peer: Arc<AtomicU64>,
    #[cfg(feature = "telemetry")]
    stats_transfer: Arc<AtomicU64>
}

#[cfg(feature = "telemetry")]
struct OverlayTelemetry {
    consumers: Arc<Metric>,
    overlays: Arc<Metric>,
    peers: Arc<Metric>,
    recv_transfers: Arc<Metric>,
    send_transfers: Arc<Metric>,
    stats_peer: Arc<Metric>,
    stats_transfer: Arc<Metric>
}

/// Overlay Node
pub struct OverlayNode {
    adnl: Arc<AdnlNode>,
    consumers: lockfree::map::Map<Arc<OverlayShortId>, ConsumerObject>,
    options: Arc<AtomicU32>,
    node_key: Arc<dyn KeyOption>, 
    overlays: lockfree::map::Map<Arc<OverlayShortId>, Arc<Overlay>>,     
    zero_state_file_hash: [u8; 32],
    #[cfg(feature = "telemetry")]
    tag_get_random_peers: u32,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<OverlayTelemetry>,
    allocated: Arc<OverlayAlloc>    
}

impl OverlayNode {

    const MAX_BROADCAST_LOG: u32 = 1000;
    const MAX_PEERS: u32 = 65536;
    const MAX_RANDOM_PEERS: u32 = 4;
    const MAX_OVERLAY_NEIGHBOURS: u32 = 200;
//    const MAX_OVERLAY_PEERS: u32 = 20;
    const MAX_SIZE_ORDINARY_BROADCAST: usize = 768;
    const TIMEOUT_GC: u64 = 1000; // Milliseconds
    const TIMEOUT_PEERS: u64 = 60000; // Milliseconds

    /// Constructor 
    pub fn with_adnl_node_and_zero_state(
        adnl: Arc<AdnlNode>, 
        zero_state_file_hash: &[u8; 32],
        key_tag: usize
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        #[cfg(feature = "telemetry")]
        let telemetry = OverlayTelemetry {
            consumers: adnl.add_metric("Alloc OVRL consumers"),
            overlays: adnl.add_metric("Alloc OVRL overlays"),
            peers: adnl.add_metric("Alloc OVRL peers"),
            recv_transfers: adnl.add_metric("Alloc OVRL recv transfers"),
            send_transfers: adnl.add_metric("Alloc OVRL send transfers"),
            stats_peer: adnl.add_metric("Alloc OVRL peer stats"),
            stats_transfer: adnl.add_metric("Alloc OVRL transfer stats"),
        };
        let allocated = OverlayAlloc {
            consumers: Arc::new(AtomicU64::new(0)),
            overlays: Arc::new(AtomicU64::new(0)),
            peers: Arc::new(AtomicU64::new(0)),
            recv_transfers: Arc::new(AtomicU64::new(0)),
            send_transfers: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "telemetry")]
            stats_peer: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "telemetry")]
            stats_transfer: Arc::new(AtomicU64::new(0))
        };
        let ret = Self { 
            adnl,
            options: Arc::new(AtomicU32::new(0)),
            consumers: lockfree::map::Map::new(),
            node_key,
            overlays: lockfree::map::Map::new(),
            zero_state_file_hash: *zero_state_file_hash,
            #[cfg(feature = "telemetry")]
            tag_get_random_peers: tag_from_boxed_type::<GetRandomPeers>(),
            #[cfg(feature = "telemetry")]
            telemetry: Arc::new(telemetry),
            allocated: Arc::new(allocated)
        };
        Ok(Arc::new(ret))
    }

    /// Add overlay data consumer
    pub fn add_consumer(
        &self, 
        overlay_id: &Arc<OverlayShortId>, 
        consumer: Arc<dyn Subscriber>
    ) -> Result<bool> {
        log::debug!(target: TARGET, "Add consumer {} to overlay", overlay_id);
        add_counted_object_to_map(
            &self.consumers,
            overlay_id.clone(),
            || {
                let ret = ConsumerObject {
                    object: consumer.clone(),
                    counter: self.allocated.consumers.clone().into()
                };
                #[cfg(feature = "telemetry")]
                self.telemetry.consumers.update(
                    self.allocated.consumers.load(Ordering::Relaxed)
                );
                Ok(ret)
            }
        )
    }

    /// Add overlay for local workchain
    pub fn add_local_workchain_overlay(
        &self, 
        runtime: Option<tokio::runtime::Handle>,
        overlay_id: &Arc<OverlayShortId>,
        hops: Option<u8>
    ) -> Result<bool> {
        self.add_overlay(runtime, overlay_id, None, 0, hops)
    }

    /// Add overlay for other workchain
    pub fn add_other_workchain_overlay(
        &self, 
        runtime: Option<tokio::runtime::Handle>,
        overlay_id: &Arc<OverlayShortId>,
        hops: Option<u8>
    ) -> Result<bool> {
        self.add_overlay(runtime, overlay_id, None, Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN, hops)
    }

    /// Add private_overlay
    pub fn add_private_overlay(
        &self, 
        runtime: Option<tokio::runtime::Handle>,
        overlay_id: &Arc<OverlayShortId>,
        overlay_key: &Arc<dyn KeyOption>, 
        peers: &[Arc<KeyId>],
        hops: Option<u8>
    ) -> Result<bool> {
        if self.add_overlay(runtime, overlay_id, Some(overlay_key.clone()), 0, hops)? {
            let overlay = self.get_overlay(overlay_id, "Cannot add the private overlay")?;
            let our_key = overlay_key.id();
            for peer in peers {
                if peer == our_key {
                    continue
                }
                overlay.known_peers.put(peer.clone())?;
            }
            overlay.update_neighbours(Self::MAX_OVERLAY_NEIGHBOURS)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Add private overlay peers 
    pub fn add_private_peers(
        &self, 
        local_adnl_key: &Arc<KeyId>, 
        peers: Vec<(IpAddress, Arc<dyn KeyOption>)>
    ) -> Result<Vec<Arc<KeyId>>> {
        let mut ret = Vec::new();
        for (ip, key) in peers {
            if let Some(peer) = self.adnl.add_peer(local_adnl_key, &ip, &key)? {
                ret.push(peer)
            }
        }
        Ok(ret)
    }

    /// Add public overlay peer 
    pub fn add_public_peer(
        &self, 
        peer_ip_address: &IpAddress, 
        peer: &Node,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<Arc<KeyId>>> {
        let overlay = self.get_overlay(overlay_id, "Trying add peer to unknown public overlay")?;
        if overlay.overlay_key.is_some() {
            fail!("Trying to add public peer to private overlay {}", overlay_id)
        }
        if let Err(e) = OverlayUtils::verify_node(overlay_id, peer) {
            log::warn!(target: TARGET, "Error when verifying Overlay peer: {}", e);
            return Ok(None)
        }
        let ret = self.adnl.add_peer(
            self.node_key.id(), 
            peer_ip_address, 
            &((&peer.id).try_into()?)
        )?;
        let ret = if let Some(ret) = ret {
            ret
        } else {
            return Ok(None)
        };
        overlay.bad_peers.remove(&ret);
        overlay.known_peers.put(ret.clone())?;
//        if overlay.random_peers.count() < Self::MAX_OVERLAY_PEERS {
//            overlay.random_peers.put(ret.clone())?;
//        }
        if overlay.neighbours.count() < Self::MAX_OVERLAY_NEIGHBOURS {
            overlay.neighbours.put(ret.clone())?;
        }  
        add_counted_object_to_map_with_update(
            &overlay.nodes,
            ret.clone(),
            |old_node| {
                if let Some(old_node) = old_node {
                    if old_node.object.version >= peer.version {
                        return Ok(None)
                    }
                }
                let ret = NodeObject {
                    object: peer.clone(),
                    counter: self.allocated.peers.clone().into()
                };
                #[cfg(feature = "telemetry")]
                self.telemetry.peers.update(
                    self.allocated.peers.load(Ordering::Relaxed)
                );
                Ok(Some(ret))
            }
        )?;
        Ok(Some(ret))
    }

    /// Broadcast message 
    pub async fn broadcast(
        &self,
        overlay_id: &Arc<OverlayShortId>, 
        data: &TaggedByteSlice<'_>, 
        source: Option<&Arc<dyn KeyOption>>,
        allow_dup: bool
    ) -> Result<BroadcastSendInfo> {
        log::trace!(target: TARGET, "Broadcast {} bytes", data.object.len());
        let overlay = self.get_overlay(overlay_id, "Trying broadcast to unknown overlay")?;
        let source = source.unwrap_or(&self.node_key);
        let overlay_key = overlay.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        if data.object.len() <= Self::MAX_SIZE_ORDINARY_BROADCAST {
            Overlay::send_broadcast(&overlay, data, source, overlay_key, allow_dup).await
        } else {
            Overlay::create_fec_send_transfer(&overlay, data, source, overlay_key, allow_dup)
        }
    } 

    /// Calculate overlay ID for public overlay
    pub fn calc_overlay_id(
        &self, 
        workchain: i32, 
        shard: i64 
    ) -> Result<OverlayId> {
        OverlayUtils::calc_overlay_id(workchain, shard, &self.zero_state_file_hash)
    }

    /// Calculate overlay short ID for public overlay
    pub fn calc_overlay_short_id(
        &self, 
        workchain: i32, 
        shard: i64 
    ) -> Result<Arc<OverlayShortId>> {
        OverlayUtils::calc_overlay_short_id(workchain, shard, &self.zero_state_file_hash)
    }

    /// Delete private_overlay
    pub fn delete_private_overlay(&self, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
        self.delete_overlay(overlay_id, true)
    }

    /// Delete public_overlay
    pub fn delete_public_overlay(&self, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
        self.delete_overlay(overlay_id, false)
    }

    /// Delete private overlay peers 
    pub fn delete_private_peers(
        &self, 
        local_key: &Arc<KeyId>, 
        peers: &[Arc<KeyId>]
    ) -> Result<bool> {
        let mut ret = false;
        for peer in peers {
            ret = self.adnl.delete_peer(local_key, peer)? || ret
        }    
        Ok(ret)
    }

    /// Delete public overlay peer 
    pub fn delete_public_peer(
        &self, 
        peer: &Arc<KeyId>,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<bool> {
        let overlay = self.get_overlay(
            overlay_id,
            "Trying to delete peer from unknown public overlay"
        )?;
        if overlay.overlay_key.is_some() {
            fail!("Trying to delete public peer from private overlay {}", overlay_id)
        }
        match overlay.bad_peers.insert_with(peer.clone(), |_, prev| prev.is_none()) {
            lockfree::set::Insertion::Created => (),
            _ => return Ok(false)
        }
//        if overlay.random_peers.contains(peer) {
//            overlay.update_random_peers(Self::MAX_OVERLAY_PEERS)?
//        }
        if overlay.neighbours.contains(peer) {
            overlay.update_neighbours(1)?
        }
        // DO NOT DELETE from ADNL, because it may be shared between overlays
        // self.adnl.delete_peer(self.node_key.id(), peer)
        Ok(true)
    }

    /// Get debug trace
    pub fn get_debug_trace(&self, overlay_id: &Arc<OverlayShortId>) -> Result<u32> {
        let overlay = self.get_overlay(overlay_id, "Getting trace from unknown overlay")?;
        Ok(overlay.debug_trace.load(Ordering::Relaxed))
    }

    /// Get locally cached random peers
    pub fn get_cached_random_peers(
        &self,
        dst: &AddressCache,  
        overlay_id: &Arc<OverlayShortId>, 
        n: u32
    ) -> Result<()> {
        let overlay = self.get_overlay(
            overlay_id, 
            "Getting cached random peers from unknown overlay"
        )?;
        overlay.known_peers.random_set(dst, Some(&overlay.bad_peers), n)
    }

    /// Get query prefix
    pub fn get_query_prefix(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Vec<u8>> {
        let overlay = self.get_overlay(overlay_id, "Getting query prefix of unknown overlay")?;
        Ok(overlay.query_prefix.clone())
    }

    /// overlay.GetRandomPeers
    pub async fn get_random_peers(
        &self, 
        dst: &Arc<KeyId>, 
        overlay_id: &Arc<OverlayShortId>,
        timeout: Option<u64>
    ) -> Result<Option<Vec<Node>>> {
        let overlay = self.get_overlay(overlay_id, "Getting random peers from unknown overlay")?;
        log::trace!(target: TARGET, "Get random peers from {}", dst);
        let query = GetRandomPeers {
            peers: self.prepare_random_peers(&overlay)?
        };
        let query = TaggedTlObject {
            object: TLObject::new(query),
            #[cfg(feature = "telemetry")]
            tag: self.tag_get_random_peers
        };
        let answer = self.query(dst, &query, overlay_id, timeout).await?;
        if let Some(answer) = answer {
            let answer: NodesBoxed = Query::parse(answer, &query.object)?;
            log::trace!(target: TARGET, "Got random peers from {}", dst);
            Ok(Some(self.process_random_peers(overlay_id, answer.only())?))
        } else {
            log::warn!(target: TARGET, "No random peers from {}", dst);
            Ok(None)
        }
    }

    /// Get signed node
    pub fn get_signed_node(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Node> {
        self.sign_local_node(overlay_id)
    }

    /// Send message via ADNL
    pub async fn message(
        &self, 
        dst: &Arc<KeyId>, 
        data: &TaggedByteSlice<'_>,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<()> {
        let overlay = self.get_overlay(overlay_id, "Sending ADNL message to unknown overlay")?;
        let src = overlay.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        #[cfg(feature = "telemetry")]
        overlay.update_stats(dst, data.tag, true)?;
        let mut buf = overlay.message_prefix.clone();
        buf.extend_from_slice(data.object);
        self.adnl.send_custom(
            &TaggedByteSlice {
                object: &buf, 
                #[cfg(feature = "telemetry")]
                tag: data.tag
            },
            &peers
        )
    }

    /// Send query via ADNL
    pub async fn query(
        &self, 
        dst: &Arc<KeyId>, 
        query: &TaggedTlObject,
        overlay_id: &Arc<OverlayShortId>,
        timeout: Option<u64>
    ) -> Result<Option<TLObject>> {
        let overlay = self.get_overlay(overlay_id, "Sending ADNL query to unknown overlay")?;
        let src = overlay.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        #[cfg(feature = "telemetry")] 
        overlay.update_stats(dst, query.tag, true)?;
        self.adnl.clone().query_with_prefix(
            Some(&overlay.query_prefix), 
            query,
            &peers,
            timeout
        ).await
    }

    /// Send query via RLDP
    pub async fn query_via_rldp(
        &self, 
        rldp: &Arc<RldpNode>,
        dst: &Arc<KeyId>, 
        data: &TaggedByteSlice<'_>,
        max_answer_size: Option<i64>,
        roundtrip: Option<u64>,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let overlay = self.get_overlay(overlay_id, "Sending RLDP query to unknown overlay")?;
        let src = overlay.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        #[cfg(feature = "telemetry")]
        overlay.update_stats(dst, data.tag, true)?;
        rldp.query(data, max_answer_size, &peers, roundtrip).await
    }

    /// Enable/disable broadcast retransmit
    pub fn set_broadcast_retransmit(&self, enabled: bool) {
        if enabled {
            self.options.fetch_and(
                !Overlay::OPTION_DISABLE_BROADCAST_RETRANSMIT, 
                Ordering::Relaxed
            );
        } else {
            self.options.fetch_or(
                Overlay::OPTION_DISABLE_BROADCAST_RETRANSMIT, 
                Ordering::Relaxed
            );
        }
    } 

    /// Statistics
    #[cfg(feature = "telemetry")]
    pub fn stats(&self) -> Result<()> {
        for overlay in self.overlays.iter() {
            overlay.val().print_stats()?
        }
        Ok(())
    } 
    
    /// Wait for broadcast
    pub async fn wait_for_broadcast(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<BroadcastRecvInfo>> {
        let overlay = self.get_overlay(overlay_id, "Waiting for broadcast in unknown overlay")?;
        if (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0 {
            fail!("Waiting for broadcast in overlay from other workchain")
        }
        overlay.received_rawbytes.pop().await
    }

    /// Wait for catchain
    pub async fn wait_for_catchain(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<(CatchainBlockUpdate, ValidatorSessionBlockUpdate, Arc<KeyId>)>> {
        self.get_overlay(overlay_id, "Waiting for catchain in unknown overlay")?
            .received_catchain.as_ref().ok_or_else(
                || error!("Waiting for catchain in public overlay {}", overlay_id)
            )?.pop().await
    }

    /// Wait for block candidate status
    pub async fn wait_for_block_candidate_status(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<(BlockCandidateStatus, Arc<KeyId>)>> {
        self.get_overlay(overlay_id, "Waiting for block candidate status in unknown overlay")?
            .received_block_status.as_ref().ok_or_else(
                || error!("Waiting for block candidate status in public overlay {}", overlay_id)
            )?.pop().await
    }

    /// Wait for peers
    pub async fn wait_for_peers(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<Vec<Node>>> {
        self.get_overlay(overlay_id, "Waiting for peers in unknown overlay")?
            .received_peers.pop().await
    }

    fn add_overlay(
        &self, 
        runtime: Option<tokio::runtime::Handle>,
        overlay_id: &Arc<OverlayShortId>, 
        overlay_key: Option<Arc<dyn KeyOption>>,
        flags: u8,
        hops: Option<u8>
    ) -> Result<bool> {
        log::debug!(target: TARGET, "Add overlay {} to node", overlay_id);
        if overlay_key.is_some() && ((flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0) {
            fail!("Cannot create private overlay {} for other workchain", overlay_id)
        }
        let added = add_counted_object_to_map(
            &self.overlays,
            overlay_id.clone(), 
            || {
                let message_prefix = OverlayMessage {
                    overlay: UInt256::with_array(*overlay_id.data())
                }.into_boxed();
                let query_prefix = OverlayQuery {
                    overlay: UInt256::with_array(*overlay_id.data())
                };
                let received_catchain = if overlay_key.is_some() {
                    let received_catchain = Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0),
                            started_listening: AtomicBool::new(false)
                        }
                    );
                    Some(received_catchain)
                } else {
                    None
                };
                let received_block_status = if overlay_key.is_some() {
                    let received_block_status = Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0),
                            started_listening: AtomicBool::new(false)
                        }
                    );
                    Some(received_block_status)
                } else {
                    None
                };
                let overlay = Overlay {
                    adnl: self.adnl.clone(),
                    bad_peers: lockfree::set::Set::new(),
                    flags,
                    hops,
                    known_peers: AddressCache::with_limit(Self::MAX_PEERS),
                    message_prefix: serialize_boxed(&message_prefix)?,
                    neighbours: AddressCache::with_limit(Self::MAX_OVERLAY_NEIGHBOURS), 
                    nodes: lockfree::map::Map::new(),
                    options: self.options.clone(),
                    overlay_id: overlay_id.clone(),
                    overlay_key: overlay_key.clone(),
                    owned_broadcasts: lockfree::map::Map::new(),
                    purge_broadcasts: lockfree::queue::Queue::new(),
                    purge_broadcasts_count: AtomicU32::new(0),
                    query_prefix: serialize_boxed(&query_prefix)?,
  //                  random_peers: AddressCache::with_limit(Self::MAX_OVERLAY_PEERS),
                    received_catchain,
                    received_block_status,
                    received_peers: Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0),
                            started_listening: AtomicBool::new(false)
                        }
                    ),
                    received_rawbytes: Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0),
                            started_listening: AtomicBool::new(false)
                        }
                    ),
                    #[cfg(feature = "telemetry")]
                    start: Instant::now(),
                    #[cfg(feature = "telemetry")]
                    print: AtomicU64::new(0),
                    #[cfg(feature = "telemetry")]
                    messages_recv: AtomicU64::new(0),
                    #[cfg(feature = "telemetry")]
                    messages_send: AtomicU64::new(0),
                    #[cfg(feature = "telemetry")]  
                    stats_per_peer_recv: lockfree::map::Map::new(),
                    #[cfg(feature = "telemetry")]  
                    stats_per_peer_send: lockfree::map::Map::new(),
                    #[cfg(feature = "telemetry")]  
                    stats_per_transfer: lockfree::map::Map::new(),
                    #[cfg(feature = "telemetry")]
                    tag_broadcast_fec: tag_from_bare_type::<BroadcastFec>(),
                    #[cfg(feature = "telemetry")]
                    tag_broadcast_ord: tag_from_bare_type::<BroadcastOrd>(),
                    #[cfg(feature = "telemetry")]
                    telemetry: self.telemetry.clone(), 
                    allocated: self.allocated.clone(),
                    debug_trace: AtomicU32::new(0),
                    counter: self.allocated.overlays.clone().into()
                };
                #[cfg(feature = "telemetry")]
                self.telemetry.overlays.update(
                    self.allocated.overlays.load(Ordering::Relaxed)
                );
                overlay.update_neighbours(Self::MAX_OVERLAY_NEIGHBOURS)?;
                Ok(Arc::new(overlay))
            }
        )?;
        if added {
            let overlay = self.get_overlay(overlay_id, "Cannot add overlay")?;
            let handle = runtime.unwrap_or_else(tokio::runtime::Handle::current);
            handle.spawn(
                async move {
                    let mut timeout_peers = 0;
                    while Arc::strong_count(&overlay) > 1 {
                        let upto = Self::MAX_BROADCAST_LOG;
                        while overlay.purge_broadcasts_count.load(Ordering::Relaxed) > upto {
                            if let Some(bcast_id) = overlay.purge_broadcasts.pop() {
                                overlay.owned_broadcasts.remove(&bcast_id);
                                #[cfg(feature = "telemetry")]
                                overlay.stats_per_transfer.remove(&bcast_id);
                            }
                            overlay.purge_broadcasts_count.fetch_sub(1, Ordering::Relaxed);
                        }
                        timeout_peers += Self::TIMEOUT_GC;
                        if timeout_peers > Self::TIMEOUT_PEERS {
//                            let result = if overlay.overlay_key.is_some() {
//                                overlay.update_neighbours(1)
//                            } else {
//                                overlay.update_random_peers(1)
//                            };
//                            if let Err(e) = result {
                            if let Err(e) = overlay.update_neighbours(1) {
                                log::error!(target: TARGET, "Error: {}", e)
                            }
                            timeout_peers = 0;
                        }
                        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_GC)).await;
                    }
                }
            );
        }
        Ok(added)
    }

    fn check_fec_broadcast_message(message: &BroadcastFec) -> Result<()> {
        const CONSTRAINTS: Constraints = Constraints {
            data_size: 32 << 20 // NOTE: 32 MB is the max reasonable data size due to 
                                // the default decoder block count assumption.
        };
        CONSTRAINTS.check_fec_type(&message.fec)?; 
        CONSTRAINTS.check_data_size(message.data_size)?;
        Constraints::check_seqno(message.seqno as u32)
    }

    fn check_overlay_adnl_address(&self, overlay: &Arc<Overlay>, adnl: &Arc<KeyId>) -> bool {
        let local_adnl = overlay.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        if local_adnl != adnl {
            log::debug!(
                target: TARGET, 
                "Bad destination ADNL address in overlay {}: expected {}, got {}", 
                overlay.overlay_id, local_adnl, adnl
            );
            false         
        } else {
            true
        }
    }

    fn delete_overlay(&self, overlay_id: &Arc<OverlayShortId>, is_private: bool) -> Result<bool> {
        let type_of = if is_private {
            "private"
        } else {
            "public"
        };
        log::debug!(target: TARGET, "Delete {} overlay {}", type_of, overlay_id);
        if let Some(overlay) = self.overlays.get(overlay_id) {
            let overlay = overlay.val();
            if is_private {
                if overlay.overlay_key.is_none() {
                    fail!("Try to delete public overlay {} as private", overlay_id)
                }
                if let Some(received_catchain) = overlay.received_catchain.as_ref() {
                    BroadcastReceiver::stop(received_catchain)
                }
                if let Some(received_block_status) = overlay.received_block_status.as_ref() {
                    BroadcastReceiver::stop(received_block_status)
                }
            } else if overlay.overlay_key.is_some() {
                fail!("Try to delete private overlay {} as public", overlay_id)
            }  
            BroadcastReceiver::stop(&overlay.received_peers);
            BroadcastReceiver::stop(&overlay.received_rawbytes);
            self.overlays.remove(overlay_id);
            log::debug!(target: TARGET, "Delete consumer {} from {} overlay", overlay_id, type_of);
            self.consumers.remove(overlay_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_overlay(&self, overlay_id: &Arc<OverlayShortId>, msg: &str) -> Result<Arc<Overlay>> {
        let ret = self.overlays.get(overlay_id).ok_or_else(
            || error!("{} {}", msg, overlay_id)
        )?.val().clone();
        Ok(ret)
    }

    fn prepare_random_peers(&self, overlay: &Overlay) -> Result<Nodes> {
        let mut ret = vec![self.sign_local_node(&overlay.overlay_id)?];
        let nodes = AddressCache::with_limit(Self::MAX_RANDOM_PEERS);
//        overlay.random_peers.random_set(&nodes, None, Self::MAX_RANDOM_PEERS)?;
        overlay.neighbours.random_set(&nodes, None, Self::MAX_RANDOM_PEERS)?;
        let (mut iter, mut current) = nodes.first();
        while let Some(node) = current {
            if let Some(node) = overlay.nodes.get(&node) {
                ret.push(node.val().object.clone())
            }
            current = nodes.next(&mut iter)
        }
        let ret = Nodes {
            nodes: ret.into()
        };
        Ok(ret)
    }

    fn process_random_peers(
        &self, 
        overlay_id: &Arc<OverlayShortId>, 
        peers: Nodes
    ) -> Result<Vec<Node>> {
        let mut ret = Vec::new();
        log::trace!(target: TARGET, "-------- Got random peers:");
        let mut peers = peers.nodes.0;
        while let Some(peer) = peers.pop() {
            let other_key: Arc<dyn KeyOption> = (&peer.id).try_into()?;
            if self.node_key.id().data() == other_key.id().data() {
                continue
            }
            log::trace!(target: TARGET, "{:?}", peer);
            if let Err(e) = OverlayUtils::verify_node(overlay_id, &peer) {
                log::warn!(target: TARGET, "Error when verifying Overlay peer: {}", e);
                continue
            }
            ret.push(peer)
        }
        Ok(ret)
    }

    fn process_get_random_peers(
        &self, 
        overlay: &Overlay, 
        query: GetRandomPeers
    ) -> Result<Option<Nodes>> {
        log::trace!(target: TARGET, "Got random peers request");
        let peers = self.process_random_peers(&overlay.overlay_id, query.peers)?;
        BroadcastReceiver::push(&overlay.received_peers, peers); 
        if (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0 {
            Ok(None)
        } else {
            Ok(Some(self.prepare_random_peers(overlay)?))
        }
    }

    fn sign_local_node(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Node> {
        let overlay = self.get_overlay(overlay_id, "Signing local node for unknown overlay")?;
        let key = overlay.overlay_key.as_ref().unwrap_or(&self.node_key);
        let version = Version::get();
        let local_node = NodeToSign {
            id: AdnlShortId {
                id: UInt256::with_array(*key.id().data())
            },
            overlay: UInt256::with_array(*overlay_id.data()),
            version 
        }.into_boxed();
        let local_node = Node {
            id: key.try_into()?,
            overlay: UInt256::with_array(*overlay_id.data()),
            signature: key.sign(&serialize_boxed(&local_node)?)?.into(),
            version
        };     
        Ok(local_node)
    }

}

#[async_trait::async_trait]
impl Subscriber for OverlayNode {

    #[cfg(feature = "telemetry")]
    async fn poll(&self, _start: &Arc<Instant>) {
        self.telemetry.consumers.update(self.allocated.consumers.load(Ordering::Relaxed));
        self.telemetry.overlays.update(self.allocated.overlays.load(Ordering::Relaxed));
        self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));        
        self.telemetry.recv_transfers.update(
            self.allocated.recv_transfers.load(Ordering::Relaxed)
        );
        self.telemetry.send_transfers.update(
            self.allocated.send_transfers.load(Ordering::Relaxed)
        );
        self.telemetry.stats_peer.update(self.allocated.stats_peer.load(Ordering::Relaxed));
        self.telemetry.stats_transfer.update(
            self.allocated.stats_transfer.load(Ordering::Relaxed)
        );
    }

    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let (mut bundle, suffix) = deserialize_boxed_bundle_with_suffix(data)?;
        if (bundle.len() < 2) || (bundle.len() > 3) {
            return Ok(false)
        }
        let have_suffix = suffix < data.len();
        let overlay_id = match bundle.remove(0).downcast::<OverlayMessageBoxed>() {
            Ok(msg) => OverlayShortId::from_data(msg.only().overlay.inner()),
            Err(msg) => {
                log::debug!(target: TARGET, "Unsupported overlay message {:?}", msg);
                return Ok(false)
            }
        };
        let overlay = self.get_overlay(&overlay_id, "Message to unknown overlay")?;
        if (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0 {
            return Ok(true)
        }
        if !self.check_overlay_adnl_address(&overlay, peers.local()) {
            return Ok(true)         
        }
        #[cfg(feature = "telemetry")] {
            let (tag, _) = bundle[0].serialize_boxed();
            overlay.update_stats(peers.other(), tag.0, false)?;
        }
        if bundle.len() == 2 {
            // Private overlay
            let catchain_update = match bundle.remove(0).downcast::<CatchainBlockUpdateBoxed>() {
                Ok(CatchainBlockUpdateBoxed::Catchain_BlockUpdate(upd)) => upd,
                Err(msg) => fail!("Unsupported private overlay message {:?}", msg)
            };
            let validator_session_update = 
                match bundle.remove(0).downcast::<ValidatorSessionBlockUpdateBoxed>() {
                    Ok(ValidatorSessionBlockUpdateBoxed::ValidatorSession_BlockUpdate(upd)) => upd,
                    Err(msg) => fail!("Unsupported private overlay message {:?}", msg)
                };
            let receiver = overlay.received_catchain.as_ref().ok_or_else(
                || error!("No catchain receiver in private overlay {}", overlay_id)
            )?;
            BroadcastReceiver::push(
                receiver, 
                (catchain_update, validator_session_update, peers.other().clone())
            );
            Ok(true)
        } else {
            let message = match bundle.remove(0).downcast::<BlockCandidateStatus>() {
                Ok(block_status) => {
                    // SMFT
                    let receiver = overlay.received_block_status.as_ref().ok_or_else(
                        || error!(
                            "No block candidate status receiver in private overlay {}", 
                            overlay_id
                        )
                    )?;
                    BroadcastReceiver::push(receiver, (block_status, peers.other().clone()));
                    return Ok(true);
                }
                Err(message) => message
            };
            // Public overlay
            let message = match message.downcast::<Broadcast>() {
                Ok(Broadcast::Overlay_BroadcastFec(bcast)) => {
                    if let Err(e) = OverlayNode::check_fec_broadcast_message(&bcast) {
                        // Ignore invalid messages as early as possible
                        log::warn!(target: TARGET, "Received bad FEC broadcast. {}", e); 
                        return Ok(true);
                    }
                    Overlay::receive_fec_broadcast(
                        &overlay, 
                        bcast, 
                        data,               
                        have_suffix,
                        peers
                    ).await?;
                    return Ok(true)
                },
                Ok(Broadcast::Overlay_Broadcast(bcast)) => {
                    Overlay::receive_broadcast(
                        &overlay, 
                        bcast, 
                        data, 
                        have_suffix,
                        peers
                    ).await?;
                    return Ok(true)
                },
                Ok(bcast) => fail!("Unsupported overlay broadcast message {:?}", bcast),
                Err(message) => message,
            };
            let consumer = if let Some(consumer) = self.consumers.get(&overlay_id) {
                consumer.val().object.clone()
            } else {
                fail!("No dedicated consumer for message {:?} in overlay {}", message, overlay_id)
            };
            match consumer.try_consume_object(message, peers).await {
                Err(msg) => fail!("Unsupported message {} in overlay {}", msg, overlay_id),
                r => r
            }
        }
    }

    async fn try_consume_query_bundle(
        &self, 
        mut objects: Vec<TLObject>,
        peers: &AdnlPeers
    ) -> Result<QueryResult> {
        if objects.len() != 2 {
            return Ok(QueryResult::RejectedBundle(objects))
        }
        let overlay_id = match objects.remove(0).downcast::<OverlayQuery>() {
            Ok(query) => OverlayShortId::from_data(query.overlay.inner()),
            Err(query) => {
                objects.insert(0, query);
                return Ok(QueryResult::RejectedBundle(objects))
            }
        };
        let overlay = if let Some(overlay) = self.overlays.get(&overlay_id) {
            overlay.val().clone()
        } else {
            fail!("Query to unknown overlay {}", overlay_id) 
        };
        if !self.check_overlay_adnl_address(&overlay, peers.local()) {
            return Ok(QueryResult::Consumed(QueryAnswer::Ready(None)))
        }
        let other_workchain = (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0;
        #[cfg(feature = "telemetry")] 
        if !other_workchain {
            let (tag, _) = objects[0].serialize_boxed();
            overlay.update_stats(peers.other(), tag.0, false)?;
        }
        let object = match objects.remove(0).downcast::<GetRandomPeers>() {
            Ok(query) => {
                return match self.process_get_random_peers(&overlay, query)? {
                    Some(answer) => QueryResult::consume(
                        answer,
                        #[cfg(feature = "telemetry")]
                        None
                    ),
                    None => Ok(QueryResult::Consumed(QueryAnswer::Ready(None)))
                }
            }
            Err(object) => object
        };
        if other_workchain {
            return Ok(QueryResult::Consumed(QueryAnswer::Ready(None)))
        }
        let consumer = if let Some(consumer) = self.consumers.get(&overlay_id) {
            consumer.val().object.clone()
        } else {
            fail!("No dedicated consumer for query {:?} in overlay {}", object, overlay_id)
        };
        match consumer.try_consume_query(object, peers).await {
            Err(msg) => fail!("Unsupported query {} in overlay {}", msg, overlay_id),
            r => r
        }
    }

}
