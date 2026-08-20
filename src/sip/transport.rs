//! 信令传输抽象
//!
//! [`Transport`] 表示一条信令连接/数据报的传输类型；
//! [`ConnectionSink`] 是服务器向某个对端发送 SIP 数据的统一出口
//! （面向流的 TLS 写入通道，或 UDP 数据报），使上层路由逻辑无需关心传输差异。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// SIP 信令传输类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS 加密传输（SIPS）
    Tls,
    /// 明文 UDP 传输
    Udp,
}

impl Transport {
    /// Via 头中的传输协议标识（如 `SIP/2.0/TLS`、`SIP/2.0/UDP`）
    pub fn via_token(&self) -> &'static str {
        match self {
            Transport::Tls => "TLS",
            Transport::Udp => "UDP",
        }
    }

    /// URI 的 transport 参数值（如 `tls`、`udp`）
    pub fn uri_param(&self) -> &'static str {
        match self {
            Transport::Tls => "tls",
            Transport::Udp => "udp",
        }
    }
}

/// 向对端发送 SIP 数据的统一出口
#[derive(Debug, Clone)]
pub enum ConnectionSink {
    /// 面向流的连接写入通道（TLS；TCP 通道由写入任务写回 socket）
    Stream(mpsc::Sender<Vec<u8>>),
    /// UDP 数据报发送（共享 socket + 目标地址）
    Udp(Arc<UdpSocket>, SocketAddr),
}

/// [`ConnectionSink::send`] 的失败原因
#[derive(Debug)]
pub enum SinkSendError {
    /// 流通道已关闭（对端断开）
    ChannelClosed,
    /// UDP 发送失败
    Io(std::io::Error),
}

impl std::fmt::Display for SinkSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkSendError::ChannelClosed => write!(f, "对端连接通道已关闭"),
            SinkSendError::Io(e) => write!(f, "UDP 发送失败: {}", e),
        }
    }
}

impl std::error::Error for SinkSendError {}

impl ConnectionSink {
    /// 该出口对应的传输类型
    pub fn transport(&self) -> Transport {
        match self {
            ConnectionSink::Stream(_) => Transport::Tls,
            ConnectionSink::Udp(_, _) => Transport::Udp,
        }
    }

    /// 发送 SIP 数据到对端
    pub async fn send(&self, data: Vec<u8>) -> Result<(), SinkSendError> {
        match self {
            ConnectionSink::Stream(tx) => tx
                .send(data)
                .await
                .map_err(|_| SinkSendError::ChannelClosed),
            ConnectionSink::Udp(socket, peer) => socket
                .send_to(&data, peer)
                .await
                .map(|_| ())
                .map_err(SinkSendError::Io),
        }
    }
}
