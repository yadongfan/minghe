//! 配置模块
//!
//! 从 config.toml 加载服务器配置，包括 SIP 服务、分机范围、TLS 证书和媒体中继等设置。

use serde::Deserialize;
use std::collections::HashMap;
use std::net::UdpSocket;

/// 应用程序顶层配置
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// SIP 服务器配置
    pub server: ServerConfig,
    /// 分机配置
    pub extensions: ExtensionConfig,
    /// TLS 证书配置
    pub tls: TlsConfig,
    /// 媒体中继配置
    pub media: MediaConfig,
    /// 分机独立密码（可选，覆盖 default_password）
    #[serde(default)]
    pub passwords: HashMap<String, String>,
}

/// SIP 服务器基本配置
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// 监听地址（如 "0.0.0.0"）
    pub listen_addr: String,
    /// SIP TLS 端口（默认 5061）
    pub sip_port: u16,
    /// 服务器域名或 IP 地址
    /// 用于 SIP URI 和 TLS 证书生成
    /// 支持域名（如 "minghe.local"）和 IP 地址（如 "192.168.1.100"）
    pub host: String,
    /// 是否启用明文 UDP 信令（默认 false）
    ///
    /// 启用后仅在 `insecure_extensions` 白名单内的分机允许通过 UDP 注册，
    /// 白名单外分机从 UDP 注册将被拒绝（403）。媒体始终为 SRTP/UDP，不受影响。
    #[serde(default)]
    pub insecure_enabled: bool,
    /// 明文 UDP 信令端口（默认 5060）
    #[serde(default = "default_insecure_port")]
    pub insecure_port: u16,
    /// 允许使用明文 UDP 信令的分机白名单
    ///
    /// `insecure_enabled = true` 时生效；列表为空表示全部拒绝（安全默认）。
    /// 分机号必须是 `range_start` ~ `range_end` 范围内的数字。
    #[serde(default)]
    pub insecure_extensions: Vec<String>,
}

/// 明文 UDP 信令端口默认值（SIP 标准端口）
fn default_insecure_port() -> u16 {
    5060
}

impl ServerConfig {
    /// 判断 host 是否为 IP 地址
    pub fn is_ip_host(&self) -> bool {
        self.host.parse::<std::net::IpAddr>().is_ok()
    }
}

/// 分机号码配置
#[derive(Debug, Clone, Deserialize)]
pub struct ExtensionConfig {
    /// 分机起始号码（含）
    pub range_start: u32,
    /// 分机结束号码（含）
    pub range_end: u32,
    /// 所有分机的默认密码
    pub default_password: String,
}

/// TLS 证书配置
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// 证书文件路径（留空则自动生成自签名证书）
    pub cert_path: String,
    /// 私钥文件路径（留空则自动生成自签名证书）
    pub key_path: String,
}

/// 媒体（RTP）中继配置
#[derive(Debug, Clone, Deserialize)]
pub struct MediaConfig {
    /// RTP 端口范围起始
    pub rtp_port_start: u16,
    /// RTP 端口范围结束
    pub rtp_port_end: u16,
    /// 服务器媒体地址（用于 SDP，留空则自动检测本机 IP）
    pub media_addr: String,
}

impl AppConfig {
    /// 从指定路径加载并解析 TOML 配置文件
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("无法读取配置文件 '{}': {}", path, e))?;
        let config: AppConfig =
            toml::from_str(&content).map_err(|e| format!("配置文件解析错误 '{}': {}", path, e))?;

        // 基本校验
        if config.extensions.range_start > config.extensions.range_end {
            return Err(format!(
                "分机范围无效: range_start ({}) > range_end ({})",
                config.extensions.range_start, config.extensions.range_end
            )
            .into());
        }

        if config.server.insecure_enabled && config.server.insecure_port == config.server.sip_port {
            return Err(format!(
                "端口冲突: insecure_port ({}) 与 sip_port ({}) 相同，明文 UDP 与 TLS 不能共用一个端口",
                config.server.insecure_port, config.server.sip_port
            )
            .into());
        }

        if config.media.rtp_port_start > config.media.rtp_port_end {
            return Err(format!(
                "RTP 端口范围无效: rtp_port_start ({}) > rtp_port_end ({})",
                config.media.rtp_port_start, config.media.rtp_port_end
            )
            .into());
        }

        if config.media.rtp_port_start % 2 != 0 {
            return Err("RTP 端口起始必须为偶数（RTP 使用偶数端口，RTCP 使用奇数端口）".into());
        }

        if config.media.media_addr.trim().is_empty() {
            return Err("media_addr 不能为空。请填写客户端可访问的服务器公网或内网 IP，否则接听后可能无声。".into());
        }

        if config.media.media_addr.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "media_addr '{}' 不是有效 IP。请填写 Bria、Linkvil 等客户端可访问的公网或内网 IP。",
                config.media.media_addr
            )
            .into());
        }

        // 校验独立密码中的分机号是否在范围内
        for (ext_str, _) in &config.passwords {
            if let Ok(ext_num) = ext_str.parse::<u32>() {
                if ext_num < config.extensions.range_start || ext_num > config.extensions.range_end
                {
                    tracing::warn!(
                        "密码配置中的分机 {} 不在有效范围 {}-{} 内，将被忽略",
                        ext_str,
                        config.extensions.range_start,
                        config.extensions.range_end
                    );
                }
            } else {
                return Err(
                    format!("密码配置中的分机号 '{}' 格式无效（应为数字）", ext_str).into(),
                );
            }
        }

        if !config.passwords.is_empty() {
            tracing::info!("已加载 {} 个分机独立密码配置", config.passwords.len());
        }

        // 校验明文 UDP 白名单
        if config.server.insecure_enabled {
            for ext in &config.server.insecure_extensions {
                if let Ok(ext_num) = ext.parse::<u32>() {
                    if ext_num < config.extensions.range_start
                        || ext_num > config.extensions.range_end
                    {
                        tracing::warn!(
                            "明文 UDP 白名单中的分机 {} 不在有效范围 {}-{} 内，该分机的 UDP 注册将被拒绝",
                            ext,
                            config.extensions.range_start,
                            config.extensions.range_end
                        );
                    }
                } else {
                    return Err(format!(
                        "明文 UDP 白名单中的分机号 '{}' 格式无效（应为数字）",
                        ext
                    )
                    .into());
                }
            }
            if config.server.insecure_extensions.is_empty() {
                tracing::warn!(
                    "已启用明文 UDP 信令但白名单为空，所有分机的 UDP 注册都将被拒绝（安全默认）"
                );
            } else {
                tracing::info!(
                    "明文 UDP 信令已启用（端口 {}），白名单分机: {}",
                    config.server.insecure_port,
                    config.server.insecure_extensions.join(", ")
                );
            }
        }

        Ok(config)
    }

    /// 检查给定的分机号码是否在配置的有效范围内
    pub fn is_valid_extension(&self, ext: u32) -> bool {
        ext >= self.extensions.range_start && ext <= self.extensions.range_end
    }

    /// 获取指定分机的密码
    ///
    /// 优先返回 [passwords] 中的独立密码，未配置则返回 default_password
    pub fn get_password(&self, extension: &str) -> &str {
        if let Some(pwd) = self.passwords.get(extension) {
            pwd
        } else {
            &self.extensions.default_password
        }
    }

    /// 获取媒体地址
    ///
    /// 如果配置中 `media_addr` 为空，则自动检测本机 IP 地址。
    pub fn get_media_addr(&self) -> String {
        if !self.media.media_addr.is_empty() {
            return self.media.media_addr.clone();
        }

        // 自动检测本机 IP
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                if socket.connect("8.8.8.8:80").is_ok() {
                    if let Ok(local_addr) = socket.local_addr() {
                        let ip = local_addr.ip().to_string();
                        tracing::info!("自动检测到本机 IP 地址: {}", ip);
                        return ip;
                    }
                }
                tracing::warn!("无法自动检测本机 IP，使用 127.0.0.1");
                "127.0.0.1".to_string()
            }
            Err(e) => {
                tracing::warn!("无法创建 UDP socket 检测本机 IP: {}，使用 127.0.0.1", e);
                "127.0.0.1".to_string()
            }
        }
    }
}
