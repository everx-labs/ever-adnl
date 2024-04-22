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
    declare_counted, dump, 
    adnl::{ 
        common::{
            add_counted_object_to_map, add_unbound_object_to_map, AdnlPeers, CountedObject,
            Counter, Query, QueryId, Subscriber, TaggedByteSlice, Version
        },
        node::{AdnlNode, DataCompression}
    }
};
#[cfg(feature = "telemetry")]
use crate::adnl::telemetry::Metric;
use rand::Rng;
use std::{
    cmp::{min, max}, sync::{Arc, atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering}}, 
    time::{Duration, Instant}
};
use ever_api::{
    deserialize_boxed, IntoBoxed, serialize_bare_inplace, serialize_boxed, 
    ton::{ //ever::{
        fec::{Type as FecType, type_::RaptorQ as FecTypeRaptorQ}, 
        rldp::{
            Message as RldpMessageBoxed, MessagePart as RldpMessagePartBoxed, 
            message::Query as RldpQuery, messagepart::Complete as RldpComplete, 
            messagepart::Confirm as RldpConfirm, messagepart::MessagePart as RldpMessagePart
        }
    }
};
#[cfg(feature = "telemetry")]
use ever_api::{tag_from_bare_object, tag_from_bare_type};
use ever_block::{error, fail, base64_encode, KeyId, Result, UInt256};
use raptor_q as raptorq;

const TARGET: &str = "rldp";

pub struct Constraints {
    pub data_size: usize,
}

impl Constraints {

    pub fn check_data_size(&self, data_size: i32) -> Result<()> {
        if data_size == 0 {
            fail!("Empty RaptorQ data payload")
        }
        if data_size as usize > self.data_size {
            fail!("Too big RaptorQ data payload: {}", data_size) 
        }
        Ok(())
    }

    pub fn check_fec_type(&self, fec_type: &FecType) -> Result<()> {
        match fec_type {
            FecType::Fec_RaptorQ(fec_type) => {
                if fec_type.symbol_size as usize != SendTransfer::SYMBOL {
                    fail!("Bad RaptorQ symbol size: {}", fec_type.symbol_size) 
                } 
                self.check_data_size(fec_type.data_size)?;                                             
            },
            x => fail!("Bad FEC type {:?}", x)
        }
        Ok(())
    }

    pub fn check_seqno(seqno: u32) -> Result<()> {
        if (seqno & 0xff000000) != 0 {
            fail!("RaptorQ seqno is longer than 24 bits: {:x}", seqno)
        }
        Ok(())
    }

}

type TransferId = [u8; 32];

/// RaptorQ decoder
pub struct RaptorqDecoder {
    engine: raptorq::Decoder,
    params: FecTypeRaptorQ,
    seqno: u32
}

impl RaptorqDecoder {

    /// Construct with parameter
    pub fn with_params(params: FecTypeRaptorQ) -> Self {
        Self {
            engine: raptorq::Decoder::new(
                raptorq::ObjectTransmissionInformation::with_defaults(
                    params.data_size as u64, 
                    params.symbol_size as u16
                )
            ),
            params,
            seqno: 0
        }
    }

    /// Decode
    pub fn decode(&mut self, seqno: u32, data: &[u8]) -> Option<Vec<u8>> {
        let packet = raptorq::EncodingPacket::new(
            raptorq::PayloadId::new(0, seqno),
            data.to_vec()
        );
        self.seqno = seqno;
        self.engine.decode(packet)
    }

    /// Parameters
    pub fn params(&self) -> &FecTypeRaptorQ {
        &self.params
    }

}

struct RecvTransfer {
    buf: Vec<u8>,
    complete: RldpComplete,
    confirm: RldpConfirm,
    confirm_count: usize,
    data: Vec<u8>,
    decoder: Option<RaptorqDecoder>,
    part: u32,
    state: Arc<RecvTransferState>,
    total_size: Option<usize>,
    #[cfg(feature = "telemetry")]
    tag_complete: u32,
    #[cfg(feature = "telemetry")]
    tag_confirm: u32
}

impl RecvTransfer {

    fn new(transfer_id: TransferId, counter: Arc<AtomicU64>) -> Self {
        let complete = RldpComplete {
            transfer_id: UInt256::with_array(transfer_id),
            part: 0
        };
        #[cfg(feature = "telemetry")]
        let tag_complete = tag_from_bare_object(&complete);
        let confirm = RldpConfirm {
            transfer_id: UInt256::with_array(transfer_id),
            part: 0,
            seqno: 0
        };
        #[cfg(feature = "telemetry")]
        let tag_confirm = tag_from_bare_object(&confirm);
        Self { 
            buf: Vec::new(),
            complete,
            confirm,
            confirm_count: 0,
            data: Vec::new(),
            decoder: None,
            part: 0,
            state: Arc::new(
                RecvTransferState {
                    updates: AtomicU32::new(0),
                    counter: counter.into()
                }
            ),
            total_size: None,
            #[cfg(feature = "telemetry")]
            tag_complete,
            #[cfg(feature = "telemetry")]
            tag_confirm
        }
    }

    fn complete_mut(&mut self) -> Result<&mut RldpComplete> {
        Ok(&mut self.complete)
    }

    fn confirm_mut(&mut self) -> Result<&mut RldpConfirm> {
        Ok(&mut self.confirm)
    }

    #[allow(clippy::boxed_local)]
    fn process_chunk(&mut self, message: RldpMessagePart) -> Result<Option<TaggedByteSlice>> {
        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = message.fec_type {
            fec_type
        } else {
            fail!("Unsupported FEC type in RLDP packet")
        };
        let total_size = if let Some(total_size) = self.total_size {
            if total_size != message.total_size as usize {
                fail!("Incorrect total size in RLDP packet")
            }
            total_size
        } else {
            let total_size = message.total_size as usize;
            self.total_size = Some(total_size);
            self.data.try_reserve_exact(total_size).map_err(
                |e| error!("RLDP message size {} is too big: {}", total_size, e)
            )?;
            total_size
        };
        let decoder = match self.part {
            part if part == message.part as u32 => {
                if let Some(decoder) = &mut self.decoder {
                    if fec_type != decoder.params {
                        fail!(
                            "Incorrect parameters in RLDP packet {:?} vs {:?}", 
                            fec_type, decoder.params
                        )
                    }
                    decoder
                } else {
                    self.decoder.get_or_insert_with(|| RaptorqDecoder::with_params(fec_type))
                }
            },
            part if part > message.part as u32 => 
                return self.build_part_completed_reply(message.part),
            _ => return Ok(None)
        };
        if let Some(mut data) = decoder.decode(message.seqno as u32, &message.data) {
            if data.len() + self.data.len() > total_size {
                fail!("Too big size for RLDP transfer")
            } else {
                self.data.append(&mut data)
            }
            if self.data.len() < total_size {
                self.decoder = None;
                self.part += 1;
                self.confirm_count = 0;
            }
            self.build_part_completed_reply(message.part) 
        } else if self.confirm_count == 9 {
            let max_seqno = decoder.seqno;
            let confirm = self.confirm_mut()?;
            confirm.part = message.part;
            confirm.seqno = max_seqno as i32;
            self.confirm_count = 0;
            serialize_bare_inplace(&mut self.buf, &self.confirm)?;
            let ret = TaggedByteSlice {
                object: &self.buf[..],
                #[cfg(feature = "telemetry")]
                tag: self.tag_confirm
            };
            Ok(Some(ret))
        } else {
            self.confirm_count += 1;
            Ok(None)
        }
    }

    fn build_part_completed_reply(&mut self, part: i32) -> Result<Option<TaggedByteSlice>> {
        self.complete_mut()?.part = part;
        serialize_bare_inplace(&mut self.buf, &self.complete)?;
        let ret = TaggedByteSlice {
            object: &self.buf[..],
            #[cfg(feature = "telemetry")]
            tag: self.tag_complete
        };
        Ok(Some(ret))
    }

}

declare_counted!(
    struct RecvTransferState {
        updates: AtomicU32
    }
);

impl RecvTransferState {
    fn updates(&self) -> u32 {
        self.updates.load(Ordering::Relaxed)
    }
    fn set_updates(&self) {
        self.updates.fetch_add(1, Ordering::Relaxed);
    }
}

/// RaptorQ encoder
pub struct RaptorqEncoder {
    encoder_index: usize,
    engine: raptorq::Encoder,
    params: FecTypeRaptorQ,
    source_packets: Vec<raptorq::EncodingPacket>
}

impl RaptorqEncoder {

    /// Construct over data
    pub fn with_data(data: &[u8]) -> Self {
        let engine = raptorq::Encoder::with_defaults(data, SendTransfer::SYMBOL as u16); 
        let mut source_packets = Vec::new();
        for encoder in engine.get_block_encoders() {
            // Reverse order to send efficiently
            let mut packets = encoder.source_packets();
            while let Some(packet) = packets.pop() {
                source_packets.push(packet)
            }
        }
        Self {
            encoder_index: 0,
            engine,
            params: FecTypeRaptorQ {
                data_size: data.len() as i32,
                symbol_size: SendTransfer::SYMBOL as i32, 
                symbols_count: source_packets.len() as i32
            },
            source_packets
        }
    }

    /// Encode 
    pub fn encode(&mut self, seqno: &mut u32) -> Result<Vec<u8>> {
        let encoders = self.engine.get_block_encoders();
        let packet = if let Some(packet) = self.source_packets.pop() {
            packet
        } else {
            let mut packets = encoders[self.encoder_index].repair_packets(*seqno, 1);
            let packet = if let Some(packet) = packets.pop() {
                packet
            } else {
                fail!("INTERNAL ERROR: cannot encode repair packet");
            };
            self.encoder_index += 1;
            if self.encoder_index >= encoders.len() {
                self.encoder_index = 0;
            }
            packet
        };
        *seqno = packet.payload_id().encoding_symbol_id();
        Ok(packet.data().to_vec())
    }

    /// Parameters
    pub fn params(&self) -> &FecTypeRaptorQ {
        &self.params
    }

}

struct SendTransfer<'a> {
    buf: Vec<u8>,
    data: &'a [u8],
    encoder: Option<RaptorqEncoder>,
    message: RldpMessagePart,
    state: Arc<SendTransferState>
}

impl <'a> SendTransfer<'a> {

    const SLICE:  usize = 2000000;
    const SYMBOL: usize = 768;
    const WINDOW: usize = 1000;

    fn new(data: &'a [u8], transfer_id: Option<TransferId>, counter: Arc<AtomicU64>) -> Self {
        let transfer_id = transfer_id.unwrap_or_else(
            || rand::thread_rng().gen()
        );
        let fec_type = FecTypeRaptorQ {
            data_size: 0,
            symbol_size: Self::SYMBOL as i32, 
            symbols_count: 0
        }.into_boxed();
        let message = RldpMessagePart {
            transfer_id: UInt256::with_array(transfer_id),
            fec_type,
            part: 0,
            total_size: 0,
            seqno: 0,
            data: Vec::new()
        };
        let state = Arc::new(SendTransferState {
            part: AtomicU32::new(0),
            reply: AtomicBool::new(false),
            seqno_sent: AtomicU32::new(0),
            seqno_recv: AtomicU32::new(0),
            counter: counter.into(),
        });
        Self {
            buf: Vec::new(), 
            data,
            encoder: None,
            message,
            state
        }
    }

    fn is_finished(&self) -> bool {
        self.state.has_reply() && 
        ((self.state.part() as usize + 1) * Self::SLICE >= self.data.len())
    }

    fn is_finished_or_next_part(&self, part: u32) -> Result<bool> {
        if self.is_finished() {
            Ok(true)
        } else {
            match self.state.part() {
                x if x == part => Ok(false),
                x if x == part + 1 => Ok(true),
                 _ => fail!("INTERNAL ERROR: part # mismatch")
            }
        }
    }

    fn message_mut(&mut self) -> Result<&mut RldpMessagePart> {
        Ok(&mut self.message)
    }

    fn prepare_chunk(&mut self) -> Result<&[u8]> {     
        if let Some(encoder) = &mut self.encoder {
            let mut seqno_sent = self.state.seqno_sent();
            let seqno_sent_original = seqno_sent;
            let chunk = encoder.encode(&mut seqno_sent)?;
            let message = self.message_mut()?;
            message.seqno = seqno_sent as i32;
            message.data = chunk;
            let seqno_recv = self.state.seqno_recv();
            if seqno_sent - seqno_recv <= Self::WINDOW as u32 {
                if seqno_sent_original == seqno_sent {
                    seqno_sent += 1;
                }
                self.state.set_seqno_sent(seqno_sent);
            }
            serialize_bare_inplace(&mut self.buf, &self.message)?;
            Ok(&self.buf[..])
        } else {
            fail!("Encoder is not ready");
        }
    }

    fn start_next_part(&mut self) -> Result<u32> {
        if self.is_finished() {
           return Ok(0);
        }
        let part = self.state.part() as usize;
        let processed = part * Self::SLICE;
        let total = self.data.len();
        if processed >= total {
           return Ok(0);
        }
        let chunk_size = min(total - processed, Self::SLICE);
        let encoder = RaptorqEncoder::with_data(
            &self.data[processed..processed + chunk_size]
        );
        let message = self.message_mut()?;
        message.part = part as i32;
        message.total_size = total as i64;
        let ret = encoder.params.symbols_count;
        match message.fec_type {
            FecType::Fec_RaptorQ(ref mut fec_type) => {
                fec_type.data_size = encoder.params.data_size;      
                fec_type.symbols_count = ret;
            },
            _ => fail!("INTERNAL ERROR: unsupported FEC type")
        }
        self.encoder = Some(encoder);
        Ok(ret as u32)
    }

}

declare_counted!(
    struct SendTransferState {
        part: AtomicU32,
        reply: AtomicBool,
        seqno_sent: AtomicU32,
        seqno_recv: AtomicU32
    }
);

impl SendTransferState {
    fn has_reply(&self) -> bool {
        self.reply.load(Ordering::Relaxed)
    }
    fn part(&self) -> u32 {
        self.part.load(Ordering::Relaxed)
    }
    fn seqno_recv(&self) -> u32 {
        self.seqno_recv.load(Ordering::Relaxed)
    }
    fn seqno_sent(&self) -> u32 {
        self.seqno_sent.load(Ordering::Relaxed)
    }
    fn set_next_part(&self, part: u32) {
        if self.part.compare_exchange(part - 1, part, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            self.seqno_sent.store(0, Ordering::Relaxed);
            self.seqno_recv.store(0, Ordering::Relaxed);
        }
    }
    fn set_reply(&self) {
        self.reply.store(true, Ordering::Relaxed)
    }
    fn set_seqno_recv(&self, seqno: u32) {
        if self.seqno_sent() >= seqno {
            let seqno_recv = self.seqno_recv();
            if seqno_recv < seqno {
                self.seqno_recv.compare_exchange(
                    seqno_recv, 
                    seqno, 
                    Ordering::Relaxed, 
                    Ordering::Relaxed
                ).ok();
            }
        }
    }
    fn set_seqno_sent(&self, seqno: u32) {
        let seqno_sent = self.seqno_sent();
        if seqno_sent < seqno {
            self.seqno_sent.compare_exchange(
                seqno_sent, 
                seqno, 
                Ordering::Relaxed, 
                Ordering::Relaxed
            ).ok();
        }
    }
}

enum RldpTransfer {
    Recv(tokio::sync::mpsc::UnboundedSender<RldpMessagePart>),
    Send(Arc<SendTransferState>),
    Done
}

struct RldpRecvContext {
    adnl: Arc<AdnlNode>, 
    peers: AdnlPeers,
    queue_reader: tokio::sync::mpsc::UnboundedReceiver<RldpMessagePart>,
    recv_transfer: RecvTransfer,
    transfer_id: TransferId
}

struct RldpSendContext<'a> {
    adnl: Arc<AdnlNode>, 
    peers: AdnlPeers,
    send_transfer: SendTransfer<'a>,
    transfer_id: TransferId,
    #[cfg(feature = "telemetry")]
    tag: u32
}

#[cfg(feature = "telemetry")]
#[derive(Default)]
struct RldpStats {
    transfers_sent_all: AtomicU64,
    transfers_recv_all: AtomicU64,
    transfers_sent_now: AtomicU64,
    transfers_recv_now: AtomicU64
}

#[cfg(feature = "telemetry")]
impl RldpStats {
    fn inc(stat: &AtomicU64) -> u64 {
        stat.fetch_add(1, Ordering::Relaxed) + 1
    }
    fn dec(stat: &AtomicU64) -> u64 {
        stat.fetch_sub(1, Ordering::Relaxed) - 1
    }
}

declare_counted!(
    struct RldpPeer {
        queries: AtomicU32,
        queue: lockfree::queue::Queue<Arc<tokio::sync::Barrier>>
    }
);

struct RldpAlloc {
    peers: Arc<AtomicU64>,
    send_transfers: Arc<AtomicU64>,
    recv_transfers: Arc<AtomicU64>
}

#[cfg(feature = "telemetry")]
struct RldpTelemetry {
    peers: Arc<Metric>,
    recv_transfers: Arc<Metric>,
    send_transfers: Arc<Metric>
}

/// Rldp Node
pub struct RldpNode {
    adnl: Arc<AdnlNode>,
    peers: lockfree::map::Map<Arc<KeyId>, RldpPeer>,
    #[cfg(feature = "telemetry")]
    stats: Arc<RldpStats>,
    subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
    transfers: Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
    #[cfg(feature = "telemetry")]
    tag_complete: u32,
    #[cfg(feature = "telemetry")]
    tag_confirm: u32,
    #[cfg(feature = "telemetry")]
    telemetry: RldpTelemetry,  
    allocated: RldpAlloc
}

impl RldpNode {

    const MAX_QUERIES: u32 = 3;
    const SIZE_TRANSFER_WAVE: u32 = 10;
    const SPINNER_MS: u64 = 10;            // Milliseconds
    const TIMEOUT_MAX_MS: u64 = 10000;     // Milliseconds
    const TIMEOUT_MIN_MS: u64 = 500;       // Milliseconds
    #[cfg(feature = "telemetry")]
    const TIMEOUT_TELEMETRY_SEC: u64 = 10; // Seconds
    
    /// Constructor 
    pub fn with_adnl_node(
        adnl: Arc<AdnlNode>, 
        subscribers: Vec<Arc<dyn Subscriber>>
    ) -> Result<Arc<Self>> {
        #[cfg(feature = "telemetry")]
        let telemetry = RldpTelemetry {
            peers: adnl.add_metric("Alloc RLDP peers"),
            recv_transfers: adnl.add_metric("Alloc RLDP recv"),
            send_transfers: adnl.add_metric("Alloc RLDP send")
        };
        let allocated = RldpAlloc {
            peers: Arc::new(AtomicU64::new(0)),
            recv_transfers: Arc::new(AtomicU64::new(0)),
            send_transfers: Arc::new(AtomicU64::new(0))
        };
        let ret = Self {
            adnl,
            peers: lockfree::map::Map::new(), 
            #[cfg(feature = "telemetry")]
            stats: Arc::new(RldpStats::default()),
            subscribers: Arc::new(subscribers),
            transfers: Arc::new(lockfree::map::Map::new()),
            #[cfg(feature = "telemetry")]
            tag_complete: tag_from_bare_type::<RldpComplete>(),
            #[cfg(feature = "telemetry")]
            tag_confirm: tag_from_bare_type::<RldpConfirm>(),
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated
        };
        Ok(Arc::new(ret))
    }

    /// Send query 
    pub async fn query(
        &self, 
        data: &TaggedByteSlice<'_>,
        max_answer_size: Option<i64>,
        peers: &AdnlPeers,
        roundtrip: Option<u64>
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let ret = self.query_transfer(data, max_answer_size, peers, roundtrip).await;
        #[cfg(feature = "telemetry")]
        match &ret {
            Err(e) => log::info!(
                target: TARGET, 
                "RLDP STAT recv: failed {:x} from {}: {}", 
                data.tag, peers.other(), e
            ),
            Ok((Some(reply), _)) => log::info!(
                target: TARGET, 
                "RLDP STAT recv: success {:x} from {}: {} bytes", 
                data.tag, peers.other(), reply.len()
            ),
            Ok((None, _)) => log::info!(
                target: TARGET, 
                "RLDP STAT recv: no data {:x} from {}", 
                data.tag, peers.other()
            )
        }
        ret
    }

    fn answer_transfer(
        &self, 
        transfer_id: &TransferId, 
        peers: &AdnlPeers
    ) -> Result<Option<tokio::sync::mpsc::UnboundedSender<RldpMessagePart>>> {
        let (queue_sender, queue_reader) = tokio::sync::mpsc::unbounded_channel();
        let inserted = add_unbound_object_to_map(
            &self.transfers, 
            *transfer_id,
            || Ok(RldpTransfer::Recv(queue_sender.clone()))
        )?;
        if !inserted {
            return Ok(None)
        }
        #[cfg(feature = "telemetry")]
        let all = RldpStats::inc(&self.stats.transfers_recv_all);
        #[cfg(feature = "telemetry")]
        let now = RldpStats::inc(&self.stats.transfers_recv_now);
        #[cfg(feature = "telemetry")]
        log::trace!(target: TARGET, "RLDP STAT recv: transfers total {}, active {}", all, now);
        let mut context = RldpRecvContext {
            adnl: self.adnl.clone(),
            peers: peers.clone(),
            queue_reader,
            recv_transfer: RecvTransfer::new(*transfer_id, self.allocated.recv_transfers.clone()),
            transfer_id: *transfer_id
        };
        #[cfg(feature = "telemetry")]
        self.telemetry.recv_transfers.update(
            self.allocated.recv_transfers.load(Ordering::Relaxed)
        );
        #[cfg(feature = "telemetry")]
        let stats = self.stats.clone();
        #[cfg(feature = "telemetry")]
        let send_metric = self.telemetry.send_transfers.clone();
        let send_counter = self.allocated.send_transfers.clone();
        let subscribers = self.subscribers.clone();
        let transfers = self.transfers.clone();
        tokio::spawn(
            async move {
                Self::receive_loop(&mut context, None).await;
                transfers.insert(context.transfer_id, RldpTransfer::Done);
                let send_transfer_id = Self::answer_transfer_loop(
                    &mut context, 
                    subscribers, 
                    transfers.clone(),
                    #[cfg(feature = "telemetry")]
                    send_metric,
                    send_counter
                ).await.unwrap_or_else(
                    |e| {
                        log::warn!(
                            target: TARGET, 
                            "ERROR: {}, transfer {}", 
                            e, base64_encode(&context.transfer_id)
                        );
                        None
                    },
                );    
                #[cfg(feature = "telemetry")]
                let all = stats.transfers_recv_all.load(Ordering::Relaxed);
                #[cfg(feature = "telemetry")]
                let now = RldpStats::dec(&stats.transfers_recv_now);
                #[cfg(feature = "telemetry")]
                log::trace!(target: TARGET, "RLDP STAT recv: transfers total {}, active {}", all, now);
                tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_MAX_MS * 2)).await;
                if let Some(send_transfer_id) = send_transfer_id {
                    transfers.remove(&send_transfer_id);
                }
                transfers.remove(&context.transfer_id);
            }
        );
        let transfers = self.transfers.clone();
        let transfer_id = *transfer_id;
        tokio::spawn(
            async move {
                tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_MAX_MS)).await;
                transfers.insert(transfer_id, RldpTransfer::Done);
            }
        );
        Ok(Some(queue_sender))
    }

    async fn answer_transfer_loop(
        context: &mut RldpRecvContext, 
        subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
        transfers: Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
        #[cfg(feature = "telemetry")]
        send_metric: Arc<Metric>,
        send_counter: Arc<AtomicU64>
    ) -> Result<Option<TransferId>> { 

        fn deserialize_query(context: &RldpRecvContext) -> Result<RldpQuery> {
            match deserialize_boxed(
               &context.recv_transfer.data[..]
            )?.downcast::<RldpMessageBoxed>() {
                Ok(RldpMessageBoxed::Rldp_Query(query)) => Ok(query),
                Ok(message) => fail!("Unexpected RLDP message: {:?}", message),
                Err(object) => fail!("Unexpected RLDP message: {:?}", object)
            }
        }

        let mut query = deserialize_query(context)?;
        let now = Version::get();
        if now > query.timeout + Self::TIMEOUT_MAX_MS as i32 / 1000 {
            fail!(
                "RLDP query was received expired on {} sec in transfer {} from {}",
                now - query.timeout,
                base64_encode(&context.transfer_id),
                context.peers.other()  
            )
        }

        let compression = if let Some(data) = DataCompression::decompress(&query.data) {
            context.adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION); 
            query.data = data;
            true
        } else {
            context.adnl.check_options(AdnlNode::OPTION_FORCE_COMPRESSION)
        };
        #[cfg(feature = "telemetry")]
        let query_tag = Self::fetch_tag(&query.data[..]);
        let Some(answer) = Query::process_rldp(&subscribers, &query, &context.peers).await? else {
            fail!("No subscribers for query {:?}", query)
        };
        let answer = match answer.try_finalize()? {
            (Some(answer), _) => answer.wait().await?,
            (None, answer) => answer
        };
        let Some(mut answer) = answer else {
            return Ok(None)
        }; 
        if compression {
            answer.object.data = DataCompression::compress(&answer.object.data)?;
        }
        let (len, max) = (answer.object.data.len(), query.max_answer_size as usize);
        if len > max {
            fail!("Exceeded max RLDP answer size: {} vs {}", len, max)
        }
        #[cfg(feature = "telemetry")]
        let tag = answer.tag;
        let data = serialize_boxed(&answer.object.into_boxed())?;
        let mut send_transfer_id = context.transfer_id;
        for x in &mut send_transfer_id {
            *x ^= 0xFF
        } 
        log::trace!(
            target: TARGET, 
            "RLDP answer to be sent in transfer {}/{} to {}",
            base64_encode(&context.transfer_id),
            base64_encode(&send_transfer_id),
            context.peers.other()  
        );
        let send_transfer = SendTransfer::new(
            &data[..], 
            Some(send_transfer_id), 
            send_counter.clone()
        );
        #[cfg(feature = "telemetry")]
        send_metric.update(send_counter.load(Ordering::Relaxed));
        transfers.insert(
            send_transfer_id, 
            RldpTransfer::Send(send_transfer.state.clone())
        );
        let context_send = RldpSendContext {
            adnl: context.adnl.clone(),
            peers: context.peers.clone(),
            send_transfer,
            transfer_id: context.transfer_id,
            #[cfg(feature = "telemetry")]
            tag
        };
        if let (true, _) = Self::send_loop(context_send, None).await? {
            log::trace!(
                target: TARGET, 
                "RLDP answer sent in transfer {} to {}",
                base64_encode(&context.transfer_id),
                context.peers.other()  
            );
            #[cfg(feature = "telemetry")]
            log::info!(
                target: TARGET, 
                "RLDP STAT send: answer on {:x} sent in transfer {} to {}",
                query_tag,
                base64_encode(&context.transfer_id),
                context.peers.other()  
            );
        } else {
            log::warn!(
                target: TARGET, 
                "Timeout on answer in RLDP transfer {} to {}", 
                base64_encode(&context.transfer_id),
                context.peers.other()  
            );
            #[cfg(feature = "telemetry")]
            log::info!(
                target: TARGET, 
                "RLDP STAT send: answer on {:x} timed out in transfer {} to {}",
                query_tag,
                base64_encode(&context.transfer_id),
                context.peers.other()  
            );
        }
        Ok(Some(send_transfer_id))

    }

    fn calc_timeout(roundtrip: Option<u64>) -> u64 {
        max(roundtrip.unwrap_or(Self::TIMEOUT_MAX_MS), Self::TIMEOUT_MIN_MS)
    }

    fn check_message(message: &RldpMessagePartBoxed) -> Result<()> {
        const CONSTRAINTS: Constraints = Constraints {
            data_size: SendTransfer::SLICE
        };
        let seqno = match message {
            RldpMessagePartBoxed::Rldp_MessagePart(part) => {
                CONSTRAINTS.check_fec_type(&part.fec_type)?;
                part.seqno
            },
            RldpMessagePartBoxed::Rldp_Confirm(confirm) => confirm.seqno,
            RldpMessagePartBoxed::Rldp_Complete(_) => return Ok(())                                                             
        };
        Constraints::check_seqno(seqno as u32) 
    }

    #[cfg(feature = "telemetry")]
    fn fetch_tag(data: &[u8]) -> u32 {
        if data.len() >= 4 {
            let mut tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            // Uncover Overlay.Query internal message if possible
            if (tag == 0xCCFD8443) && (data.len() >= 40) {
                tag = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
            }
            tag
        } else {
            0
        }
    }

    fn is_timed_out(timeout: u64, updates: u32, start: &Instant) -> bool {
        start.elapsed().as_millis() as u64 > timeout + timeout * updates as u64 / 100
    }

    #[cfg(feature = "telemetry")]
    fn print_stats(&self) {
    }

    async fn query_transfer(
        &self, 
        query_data: &TaggedByteSlice<'_>,
        max_answer_size: Option<i64>,
        peers: &AdnlPeers,
        roundtrip: Option<u64>
    ) -> Result<(Option<Vec<u8>>, u64)> {  
        let data = if self.adnl.check_options(AdnlNode::OPTION_FORCE_COMPRESSION) {
            DataCompression::compress(&query_data.object)?
        } else {
            query_data.object.to_vec()
        };
        let query_id: QueryId = rand::thread_rng().gen();
        let message = RldpQuery {
            query_id: UInt256::with_array(query_id),
            max_answer_size: max_answer_size.unwrap_or(128 * 1024),
            timeout: Version::get() + Self::TIMEOUT_MAX_MS as i32/1000,
            data
        }.into_boxed();
        let data = serialize_boxed(&message)?;
        let peer = if let Some(peer) = self.peers.get(peers.other()) {
            peer
        } else {
            add_counted_object_to_map(
                &self.peers, 
                peers.other().clone(),
                || {
                    let ret = RldpPeer {
                        queries: AtomicU32::new(0),
                        queue: lockfree::queue::Queue::new(),
                        counter: self.allocated.peers.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));
                    Ok(ret)
                }
            )?;
            if let Some(peer) = self.peers.get(peers.other()) {
                peer
            } else {
                fail!("Cannot find RLDP peer {}", peers.other())
            }           
        };
        let peer = peer.val();
        let queries = peer.queries.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "telemetry")]
        log::trace!(
            target: TARGET, 
            "RLDP STAT send: peer {} queries queued: {}", 
            peers.other(), queries
        );
        if queries >= Self::MAX_QUERIES {
            let ping = Arc::new(tokio::sync::Barrier::new(2));
            peer.queue.push(ping.clone());
            ping.wait().await;
        }                                                 	
        #[cfg(feature = "telemetry")]
        let all = RldpStats::inc(&self.stats.transfers_sent_all);
        #[cfg(feature = "telemetry")]
        let now = RldpStats::inc(&self.stats.transfers_sent_now);
        #[cfg(feature = "telemetry")]
        log::trace!(target: TARGET, "RLDP STAT send: transfers total {}, active {}", all, now);
        let send_transfer = SendTransfer::new(
            &data[..], 
            None, 
            self.allocated.send_transfers.clone()
        );
        let send_transfer_id = send_transfer.message.transfer_id.as_array().clone();
        self.transfers.insert(
            send_transfer_id, 
            RldpTransfer::Send(send_transfer.state.clone())
        );
        let mut recv_transfer_id = send_transfer_id;
        for x in &mut recv_transfer_id {
            *x ^= 0xFF
        } 
        let (queue_sender, queue_reader) = tokio::sync::mpsc::unbounded_channel();
        let recv_transfer = RecvTransfer::new(
            recv_transfer_id,
            self.allocated.recv_transfers.clone()
        );
        #[cfg(feature = "telemetry")]
        self.telemetry.recv_transfers.update(
            self.allocated.recv_transfers.load(Ordering::Relaxed)
        );
        self.transfers.insert(
            recv_transfer_id, 
            RldpTransfer::Recv(queue_sender)
        );
        let send_context = RldpSendContext {
            adnl: self.adnl.clone(),
            peers: peers.clone(),
            send_transfer,
            transfer_id: send_transfer_id,
            #[cfg(feature = "telemetry")]
            tag: query_data.tag
        };
        let recv_context = RldpRecvContext {
            adnl: self.adnl.clone(),
            peers: peers.clone(),
            queue_reader,
            recv_transfer,
            transfer_id: send_transfer_id
        };
        log::trace!(
            target: TARGET, 
            "transfer id {}/{}, total to send {}", 
            base64_encode(&send_transfer_id), 
            base64_encode(&recv_transfer_id), 
            data.len()
        );
        let res = self
            .query_transfer_loop(send_context, recv_context, &recv_transfer_id, roundtrip)
            .await;
        if res.is_err() {
            self.transfers.insert(send_transfer_id, RldpTransfer::Done);
        }
        self.transfers.insert(recv_transfer_id, RldpTransfer::Done);
        let transfers = self.transfers.clone();
        tokio::spawn(
            async move {
                tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_MAX_MS * 2)).await;
                transfers.remove(&send_transfer_id); 
                transfers.remove(&recv_transfer_id); 
            }
        );        
        #[cfg(feature = "telemetry")]
        let all = self.stats.transfers_sent_all.load(Ordering::Relaxed);
        #[cfg(feature = "telemetry")]
        let now = RldpStats::dec(&self.stats.transfers_sent_now);
        #[cfg(feature = "telemetry")]
        log::trace!(target: TARGET, "RLDP STAT send: transfers total {}, actual {}", all, now);
        let queries = peer.queries.fetch_sub(1, Ordering::Relaxed);
        #[cfg(feature = "telemetry")]
        log::trace!(
            target: TARGET, 
            "RLDP STAT send: peer {} queries queued: {}", 
            peers.other(), queries
        );
        if queries > Self::MAX_QUERIES {
            loop {
                if let Some(pong) = peer.queue.pop() {
                    pong.wait().await;
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        let (answer, roundtrip) = res?;
        if let Some(answer) = answer {
            match deserialize_boxed(&answer[..])?.downcast::<RldpMessageBoxed>() {
                Ok(RldpMessageBoxed::Rldp_Answer(answer)) => 
                    if answer.query_id.as_slice() != &query_id {
                        fail!("Unknown query ID in RLDP answer")
                    } else {
                        let data = match DataCompression::decompress(&answer.data) {
                            Some(data) => {
                                self.adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
                                data
                            },
                            None => answer.data.to_vec() 
                        };
                        log::trace!(
                            target: TARGET, 
                            "RLDP answer {:02x}{:02x}{:02x}{:02x}...", 
                            data[0], data[1], data[2], data[3]
                        );
                        Ok((Some(data), roundtrip))
                    },
                Ok(answer) => 
                    fail!("Unexpected answer to RLDP query: {:?}", answer),
                Err(answer) => 
                    fail!("Unexpected answer to RLDP query: {:?}", answer)
            }
        } else {
            Ok((None, roundtrip))
        }        
    }

    async fn query_transfer_loop(
        &self, 
        send_context: RldpSendContext<'_>, 
        mut recv_context: RldpRecvContext, 
        recv_transfer_id: &TransferId,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let ping = Arc::new(lockfree::queue::Queue::new());
        let pong = ping.clone();
        let peers = send_context.peers.clone();
        let recv_state = recv_context.recv_transfer.state.clone();
        let send_state = send_context.send_transfer.state.clone();
        let send_transfer_id = send_context.transfer_id;
        tokio::spawn(
            async move {
                Self::receive_loop(&mut recv_context, Some(send_state)).await;
                pong.push(recv_context.recv_transfer)
            }
        );
        let (ok, mut roundtrip) = Self::send_loop(send_context, roundtrip).await?;
        let mut timeout = Self::calc_timeout(Some(roundtrip));
        self.transfers.insert(send_transfer_id, RldpTransfer::Done);
        if ok {
            log::trace!(
                target: TARGET, 
                "RLDP query sent in transfer {}/{} to {}, waiting for answer",
                base64_encode(&send_transfer_id),
                base64_encode(&recv_transfer_id),
                peers.other()
            )
        } else {
            log::warn!(
                target: TARGET, 
                "Timeout ({} ms) on query in RLDP transfer {}/{} to {}",
                timeout,
                base64_encode(&send_transfer_id),
                base64_encode(&recv_transfer_id),
                peers.other()
            );
            return Ok((None, roundtrip));
        }
        let mut start_part = Instant::now();
        let mut updates = recv_state.updates();
        loop {
            tokio::time::sleep(Duration::from_millis(Self::SPINNER_MS)).await;
            let new_updates = recv_state.updates();
            if new_updates > updates {
                log::trace!(
                    target: TARGET, 
                    "Recv updates {} -> {} in transfer {}/{}", 
                    updates, new_updates, 
                    base64_encode(&send_transfer_id),
                    base64_encode(&recv_transfer_id)
                );
                timeout = Self::update_roundtrip(&mut roundtrip, &start_part);
                updates = new_updates;
                start_part = Instant::now();
            } else if Self::is_timed_out(timeout, updates, &start_part) {
                log::warn!(
                    target: TARGET, 
                    "No activity for transfer {}/{} to {} in {} ms, aborting", 
                    base64_encode(&send_transfer_id),
                    base64_encode(&recv_transfer_id),
                    peers.other(),
                    timeout
                );
                break
            }
            if let Some(reply) = ping.pop() {
                log::trace!(                  
                    target: TARGET, 
                    "Got reply for transfer {}/{} from {}", 
                    base64_encode(&send_transfer_id),
                    base64_encode(&recv_transfer_id),
                    peers.other()
                );
                Self::update_roundtrip(&mut roundtrip, &start_part);
                return Ok((Some(reply.data), roundtrip))
            }
        }
        Ok((None, roundtrip))
    }

    async fn receive_loop(
        context: &mut RldpRecvContext,
        mut send_state: Option<Arc<SendTransferState>>
    ) {
        while let Some(job) = context.queue_reader.recv().await {
            let begin = context.recv_transfer.data.is_empty();
            match context.recv_transfer.process_chunk(job) {
                Err(e) => log::warn!(target: TARGET, "RLDP error: {}", e),
                Ok(Some(reply)) => {
                    if let Err(e) = context.adnl.send_custom(&reply, &context.peers) {
                        log::warn!(target: TARGET, "RLDP reply error: {}", e)
                    }
                },
                _ => ()
            }
            context.recv_transfer.state.set_updates();
            if let Some(send_state) = send_state.take() {
                send_state.set_reply();                    
            }
            if begin && !context.recv_transfer.data.is_empty() {
                log::trace!(
                    target: TARGET,
                    "transfer id {}, received first {}, total to receive {:?}",
                    base64_encode(&context.transfer_id),
                    context.recv_transfer.data.len(),
                    context.recv_transfer.total_size
                );              
                let len = min(64, context.recv_transfer.data.len());              
                dump!(trace, TARGET, "PACKET #0", &context.recv_transfer.data[..len]);
            }
            if let Some(total_size) = context.recv_transfer.total_size {
                if total_size == context.recv_transfer.data.len() {
                    log::trace!(
                        target: TARGET, 
                        "transfer id {}, receive completed ({})",
                        base64_encode(&context.transfer_id),
                        total_size,
                    );
                    break
                }
            } else {
                log::warn!("INTERNAL ERROR: RLDP total size mismatch")
            }
        }   
        // Graceful close
        context.queue_reader.close();
        while context.queue_reader.recv().await.is_some() {
        }
    }

    async fn send_loop(
        mut context: RldpSendContext<'_>, 
        roundtrip: Option<u64>
    ) -> Result<(bool, u64)> {
        let mut timeout = Self::calc_timeout(roundtrip);
        let mut roundtrip = roundtrip.unwrap_or(0);
        loop {
            let mut transfer_wave = context.send_transfer.start_next_part()?;
            if transfer_wave == 0 {
                break;
            }
            transfer_wave = min(transfer_wave, Self::SIZE_TRANSFER_WAVE);
            let part = context.send_transfer.state.part();
            let mut start_part = Instant::now();
            let mut recv_seqno = 0;
            'part: loop {                            
                for _ in 0..transfer_wave {
                    let chunk = TaggedByteSlice {
                        object: context.send_transfer.prepare_chunk()?, 
                        #[cfg(feature = "telemetry")]
                        tag: context.tag
                    };
                    context.adnl.send_custom(&chunk, &context.peers)?;
                    if context.send_transfer.is_finished_or_next_part(part)? {
                        break 'part;
                    }
                }                                                                                                                         
                tokio::time::sleep(Duration::from_millis(Self::SPINNER_MS)).await;
                if context.send_transfer.is_finished_or_next_part(part)? {
                    break;
                }
                let new_recv_seqno = context.send_transfer.state.seqno_recv();
                if new_recv_seqno > recv_seqno {
                    log::trace!(
                        target: TARGET, 
                        "Send updates {} -> {} in transfer {}", 
                        recv_seqno, new_recv_seqno, base64_encode(&context.transfer_id)
                    );
                    timeout = Self::update_roundtrip(&mut roundtrip, &start_part);
                    recv_seqno = new_recv_seqno;
                    start_part = Instant::now();
                } else if Self::is_timed_out(timeout, recv_seqno, &start_part) {
                    return Ok((false, min(roundtrip * 2, Self::TIMEOUT_MAX_MS)))
                }                
            }
            timeout = Self::update_roundtrip(&mut roundtrip, &start_part);
        }
        Ok((true, roundtrip))
    }

    fn update_roundtrip(roundtrip: &mut u64, start: &Instant) -> u64{
        *roundtrip = if *roundtrip == 0 {
            start.elapsed().as_millis() as u64
        } else {
            (*roundtrip + start.elapsed().as_millis() as u64) / 2
        };
        Self::calc_timeout(Some(*roundtrip)) 
    }

}

#[async_trait::async_trait]
impl Subscriber for RldpNode {

    #[cfg(feature = "telemetry")]
    async fn poll(&self, start: &Arc<Instant>) {
        if ((start.elapsed().as_secs() + 1) % Self::TIMEOUT_TELEMETRY_SEC) == 0 {
            self.print_stats()
        }
        self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));        
        self.telemetry.recv_transfers.update(
            self.allocated.recv_transfers.load(Ordering::Relaxed)
        );
        self.telemetry.send_transfers.update(
            self.allocated.send_transfers.load(Ordering::Relaxed)
        );
    }

    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let msg = if let Ok(msg) = deserialize_boxed(data) {
            msg
        } else {
            return Ok(false)
        };
        let msg = if let Ok(msg) = msg.downcast::<RldpMessagePartBoxed>() { 
            msg
        } else {
            return Ok(false)
        };
        if let Err(e) = RldpNode::check_message(&msg) {
            // Ignore invalid messages as early as possible
            log::warn!(target: TARGET, "Received bad RLDP message. {}", e);
            return Ok(true)
        }
        match msg {
            RldpMessagePartBoxed::Rldp_Complete(msg) => {
                if let Some(transfer) = self.transfers.get(msg.transfer_id.as_slice()) {
                    if let RldpTransfer::Send(transfer) = transfer.val() {
                        transfer.set_next_part(msg.part as u32 + 1);
                    }
                }
            },
            RldpMessagePartBoxed::Rldp_Confirm(msg) => {
                if let Some(transfer) = self.transfers.get(msg.transfer_id.as_slice()) {
                    if let RldpTransfer::Send(transfer) = transfer.val() {
                        if transfer.part() == msg.part as u32 {
                            transfer.set_seqno_recv(msg.seqno as u32);
                        }
                    }
                }
            },
            RldpMessagePartBoxed::Rldp_MessagePart(msg) => {
                let transfer_id = msg.transfer_id.as_slice();
                loop {
                    let result = if let Some(transfer) = self.transfers.get(transfer_id) {
                        if let RldpTransfer::Recv(queue_sender) = transfer.val() {   
                            queue_sender.send(msg)
                        } else {
                            let reply = RldpConfirm {
                                transfer_id: msg.transfer_id.clone(),
                                part: msg.part,
                                seqno: msg.seqno
                            }.into_boxed();
                            self.adnl.send_custom(
                                &TaggedByteSlice {
                                    object: &serialize_boxed(&reply)?[..], 
                                    #[cfg(feature = "telemetry")]
                                    tag: self.tag_confirm
                                },
                                &peers,
                            )?;
                            let reply = RldpComplete {
                                transfer_id: msg.transfer_id.clone(),
                                part: msg.part
                            }.into_boxed();
                            self.adnl.send_custom(
                                &TaggedByteSlice {
                                    object: &serialize_boxed(&reply)?[..], 
                                    #[cfg(feature = "telemetry")]
                                    tag: self.tag_complete
                                },
                                &peers
                            )?;
                            log::info!(
                                target: TARGET, 
                                "Receive update on closed RLDP transfer {}, part {}, seqno {}",
                                base64_encode(transfer_id), msg.part, msg.seqno
                            );
                            break
                        }
                    } else if let Some(queue_sender) = self.answer_transfer(transfer_id, peers)? {
                        queue_sender.send(msg)
                    } else {
                        continue
                    };
                    match result {
                        Ok(()) => (),
                        Err(tokio::sync::mpsc::error::SendError(_)) => ()
                    }
                    break
                }
            }
        }
        Ok(true) 
    }

}
