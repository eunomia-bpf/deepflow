use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Weak,
};
use std::thread;
use std::time::Duration;

use arc_swap::access::Access;
use log::{debug, error, info, warn};
use thread::JoinHandle;

use super::{SendItem, SendMessageType};
use crate::config::handler::SenderAccess;
use crate::exception::ExceptionHandler;
use crate::proto::trident::Exception;
use crate::utils::{
    queue::{Error, Receiver},
    stats::{Collector, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption},
};

#[derive(Debug, Default)]
pub struct SenderCounter {
    pub tx: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub dropped: AtomicU64,
}

impl RefCountable for SenderCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "tx",
                CounterType::Counted,
                CounterValue::Unsigned(self.tx.swap(0, Ordering::Relaxed)),
            ),
            (
                "tx-bytes",
                CounterType::Counted,
                CounterValue::Unsigned(self.tx_bytes.swap(0, Ordering::Relaxed)),
            ),
            (
                "dropped",
                CounterType::Counted,
                CounterValue::Unsigned(self.dropped.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

#[derive(Debug)]
struct Header {
    frame_size: u32, // tcp发送时，需要按此长度收齐数据后，再decode (FrameSize总长度，包含了 BaseHeader的长度)
    msg_type: SendMessageType,

    version: u32,  // 用来校验encode和decode是否配套
    sequence: u64, // 依次递增，接收方用来判断是否有丢包(UDP发送时)
    vtap_id: u16,  // roze用来上报trisolaris活跃的VTAP信息
}

impl Header {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.frame_size.to_be_bytes().as_slice());
        buffer.push(self.msg_type.into());
        buffer.extend_from_slice(self.version.to_le_bytes().as_slice());
        buffer.extend_from_slice(self.sequence.to_le_bytes().as_slice());
        buffer.extend_from_slice(self.vtap_id.to_le_bytes().as_slice());
    }
}

struct Encoder {
    id: usize,
    header: Header,

    buffer: Vec<u8>,
}

impl Encoder {
    const BUFFER_LEN: usize = 8192;
    pub fn new(id: usize, msg_type: SendMessageType, vtap_id: u16) -> Self {
        Self {
            id,
            buffer: Vec::with_capacity(Self::BUFFER_LEN),
            header: Header {
                msg_type,
                frame_size: 0,
                version: 0,
                sequence: 0,
                vtap_id,
            },
        }
    }

    fn set_msg_type_and_version(&mut self, s: &SendItem) {
        if self.header.version != 0 {
            return;
        }
        self.header.msg_type = s.message_type();
        self.header.version = s.version();
    }

    pub fn cache_to_sender(&mut self, s: SendItem) {
        if self.buffer.is_empty() {
            self.set_msg_type_and_version(&s);
            self.add_header();
        }
        // 预留4个字节pb长度
        let offset = self.buffer.len();
        self.buffer.extend_from_slice([0u8; 4].as_slice());
        match s.encode(&mut self.buffer) {
            Ok(size) => self.buffer[offset..offset + 4]
                .copy_from_slice((size as u32).to_le_bytes().as_slice()),
            Err(e) => debug!("encode failed {}", e),
        };
    }

    fn add_header(&mut self) {
        self.header.sequence += 1;
        self.header.encode(&mut self.buffer);
    }

    pub fn set_header_frame_size(&mut self) {
        let frame_size = self.buffer.len() as u32;
        self.buffer[0..4].copy_from_slice(frame_size.to_be_bytes().as_slice());
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn get_buffer(&mut self) -> Vec<u8> {
        self.buffer.drain(..).collect()
    }
}

pub struct UniformSenderThread {
    id: usize,
    input: Arc<Receiver<SendItem>>,
    config: SenderAccess,

    thread_handle: Option<JoinHandle<()>>,

    running: Arc<AtomicBool>,
    stats: Arc<Collector>,
    exception_handler: ExceptionHandler,
}

impl UniformSenderThread {
    pub fn new(
        id: usize,
        input: Receiver<SendItem>,
        config: SenderAccess,
        stats: Arc<Collector>,
        exception_handler: ExceptionHandler,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(false));
        Self {
            id,
            input: Arc::new(input),
            config,
            thread_handle: None,
            running,
            stats,
            exception_handler,
        }
    }

    pub fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            warn!(
                "uniform sender id: {} already started, do nothing.",
                self.id
            );
            return;
        }

        let mut uniform_sender = UniformSender::new(
            self.id,
            self.input.clone(),
            self.config.clone(),
            self.running.clone(),
            self.stats.clone(),
            self.exception_handler.clone(),
        );
        self.thread_handle = Some(thread::spawn(move || uniform_sender.process()));
        info!("uniform sender id: {} started", self.id);
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "uniform sender id: {} already stopped, do nothing.",
                self.id
            );
            return;
        }
        info!("stoping uniform sender id: {}", self.id);
        let _ = self.thread_handle.take().unwrap().join();
        info!("stopped uniform sender id: {}", self.id);
    }
}

pub struct UniformSender {
    id: usize,

    input: Arc<Receiver<SendItem>>,
    counter: Arc<SenderCounter>,

    tcp_stream: Option<TcpStream>,
    encoder: Encoder,
    last_flush: Duration,

    dst_ip: IpAddr,
    config: SenderAccess,
    reconnect: bool,

    running: Arc<AtomicBool>,
    stats: Arc<Collector>,
    stats_registered: bool,
    exception_handler: ExceptionHandler,
}

impl UniformSender {
    const DST_PORT: u16 = 20033;
    const TCP_WRITE_TIMEOUT: u64 = 3; // s
    const QUEUE_READ_TIMEOUT: u64 = 3; // s

    pub fn new(
        id: usize,
        input: Arc<Receiver<SendItem>>,
        config: SenderAccess,
        running: Arc<AtomicBool>,
        stats: Arc<Collector>,
        exception_handler: ExceptionHandler,
    ) -> Self {
        Self {
            id,
            input,
            counter: Arc::new(SenderCounter::default()),
            encoder: Encoder::new(0, SendMessageType::TaggedFlow, config.load().vtap_id),
            last_flush: Duration::ZERO,
            dst_ip: config.load().dest_ip,
            config,
            tcp_stream: None,
            reconnect: false,
            running,
            stats,
            stats_registered: false,
            exception_handler,
        }
    }

    fn update_dst_ip(&mut self) {
        if self.dst_ip != self.config.load().dest_ip {
            info!(
                "update dst ip from {} to {}",
                self.dst_ip,
                self.config.load().dest_ip
            );
            self.reconnect = true;
            self.dst_ip = self.config.load().dest_ip;
        }
    }

    fn flush_encoder(&mut self) {
        if self.encoder.buffer_len() > 0 {
            self.encoder.set_header_frame_size();
            let buffer = self.encoder.get_buffer();
            self.send_buffer(buffer.as_slice());
        }
    }

    fn send_buffer(&mut self, buffer: &[u8]) {
        if self.reconnect || self.tcp_stream.is_none() {
            if let Some(t) = self.tcp_stream.take() {
                if let Err(e) = t.shutdown(Shutdown::Both) {
                    debug!("tcp stream shutdown failed {}", e);
                }
            }
            self.tcp_stream = TcpStream::connect((self.dst_ip, Self::DST_PORT)).ok();
            if let Some(tcp_stream) = self.tcp_stream.as_mut() {
                if let Err(e) =
                    tcp_stream.set_write_timeout(Some(Duration::from_secs(Self::TCP_WRITE_TIMEOUT)))
                {
                    debug!("tcp stream set write timeout failed {}", e);
                    self.tcp_stream.take();
                    return;
                }
                self.reconnect = false;
            } else {
                if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                    self.exception_handler.set(Exception::AnalyzerSocketError);
                    error!(
                        "tcp connection to {}:{} failed",
                        self.dst_ip,
                        Self::DST_PORT
                    );
                }
                self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let tcp_stream = self.tcp_stream.as_mut().unwrap();

        let mut write_offset = 0usize;
        loop {
            let result = tcp_stream.write(&buffer[write_offset..]);
            match result {
                Ok(size) => {
                    write_offset += size;
                    if write_offset == buffer.len() {
                        self.counter.tx.fetch_add(1, Ordering::Relaxed);
                        self.counter
                            .tx_bytes
                            .fetch_add(buffer.len() as u64, Ordering::Relaxed);
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    debug!("tcp stream write data block {}", e);
                    continue;
                }
                Err(e) => {
                    if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                        self.exception_handler.set(Exception::AnalyzerSocketError);
                        error!(
                            "tcp stream write data to {}:{} failed: {}",
                            self.dst_ip,
                            Self::DST_PORT,
                            e
                        );
                    }
                    self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                    self.tcp_stream.take();
                    break;
                }
            };
        }
    }

    fn check_or_register_counterable(&mut self) {
        if self.stats_registered {
            return;
        }
        self.stats.register_countable(
            "collect_sender",
            Countable::Ref(Arc::downgrade(&self.counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag(
                "type",
                format!("{}", self.encoder.header.msg_type).to_string(),
            )],
        );
        self.stats_registered = true;
    }

    pub fn process(&mut self) {
        while self.running.load(Ordering::Relaxed) {
            match self
                .input
                .recv(Some(Duration::from_secs(Self::QUEUE_READ_TIMEOUT)))
            {
                Ok(send_item) => {
                    debug!("send item: {}", send_item);
                    self.encoder.cache_to_sender(send_item);
                    if self.encoder.buffer_len() > Encoder::BUFFER_LEN {
                        self.check_or_register_counterable();
                        self.update_dst_ip();
                        self.flush_encoder();
                    }
                }
                Err(Error::Timeout) => {
                    self.update_dst_ip();
                    self.flush_encoder();
                }
                Err(Error::Terminated(_, _)) => {
                    self.flush_encoder();
                    break;
                }
            }
        }
    }
}