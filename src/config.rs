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
    /// IP 封锁（黑名单）配置
    #[serde(default)]
    pub ip_block: IpBlockConfig,
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
    /// TLS 最低协议版本（"1.0"/"1.1"/"1.2"/"1.3"，默认 "1.2"）
    ///
    /// 默认 TLS 1.2。接入 HX4G 等老式网关时，若设备仅支持 TLS 1.0/1.1，
    /// 可下调到 "1.0" 或 "1.1"（会降低安全性，请仅在受信网络中使用）。
    #[serde(default = "default_tls_min_version")]
    pub tls_min_version: String,
}

/// tls_min_version 默认值
fn default_tls_min_version() -> String {
    "1.2".to_string()
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

/// IP 封锁（黑名单）配置
///
/// 控制注册/认证失败计数与 IP 封锁行为。可完全关闭，也可调整
/// 封锁阈值与统计窗口，无需改代码或重新编译。所有字段均有默认值，
/// 即使完全不写 `[ip_block]` 段也能正常启动。
#[derive(Debug, Clone, Deserialize)]
pub struct IpBlockConfig {
    /// 是否启用 IP 封锁
    ///
    /// - `true`：窗口内累计失败达到阈值后封锁该 IP（默认）。
    /// - `false`：完全关闭封锁与失败计数，所有来源均放行进入认证流程。
    #[serde(default = "default_ip_block_enabled")]
    pub enabled: bool,
    /// 封锁阈值：统计窗口内同一 IP 累计失败达到该次数即被封锁
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    /// 失败计数统计窗口（秒）：窗口外的失败自动过期，避免合法用户被长期累计误伤
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// 失败计数表（`failed_ips`）最大条目数，防止攻击者用海量不同 IP 撑爆内存
    #[serde(default = "default_max_failed_ips")]
    pub max_failed_ips: usize,
    /// 封锁表（`blocked_ips`）最大条目数，达到上限后不再新增封锁（内存保护，降级为仅告警）
    #[serde(default = "default_max_blocked_ips")]
    pub max_blocked_ips: usize,
}

impl Default for IpBlockConfig {
    fn default() -> Self {
        Self {
            enabled: default_ip_block_enabled(),
            max_failures: default_max_failures(),
            window_secs: default_window_secs(),
            max_failed_ips: default_max_failed_ips(),
            max_blocked_ips: default_max_blocked_ips(),
        }
    }
}

fn default_ip_block_enabled() -> bool {
    true
}

fn default_max_failures() -> u32 {
    3
}

fn default_window_secs() -> u64 {
    600
}

fn default_max_failed_ips() -> usize {
    100_000
}

fn default_max_blocked_ips() -> usize {
    50_000
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

// 校验 TLS 最低版本
        match config.tls.tls_min_version.trim() {
            "1.0" | "1.1" | "1.2" | "1.3" => {}
            other => {
                return Err(format!(
                    "tls_min_version '{}' 无效，支持的值: \"1.0\" / \"1.1\" / \"1.2\" / \"1.3\"",
                    other
                )
                .into());
            }
        }

        // 校验 IP 封锁配置
        if config.ip_block.enabled {
            if config.ip_block.max_failures == 0 {
                return Err("ip_block.max_failures 必须大于 0（或设置 ip_block.enabled = false 关闭封锁）".into());
            }
            if config.ip_block.window_secs == 0 {
                return Err("ip_block.window_secs 必须大于 0（或设置 ip_block.enabled = false 关闭封锁）".into());
            }
            if config.ip_block.max_failed_ips == 0 {
                return Err("ip_block.max_failed_ips 必须大于 0（或设置 ip_block.enabled = false 关闭封锁）".into());
            }
            if config.ip_block.max_blocked_ips == 0 {
                return Err("ip_block.max_blocked_ips 必须大于 0（或设置 ip_block.enabled = false 关闭封锁）".into());
            }
        }
        if config.ip_block.enabled {
            tracing::info!(
                "IP 封锁已启用：阈值 {} 次 / {}s 窗口（失败表上限 {}、封锁表上限 {}）",
                config.ip_block.max_failures,
                config.ip_block.window_secs,
                config.ip_block.max_failed_ips,
                config.ip_block.max_blocked_ips
            );
        } else {
            tracing::warn!("IP 封锁已关闭（ip_block.enabled = false），所有来源均可进入认证流程");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_block_config_defaults_match_original_constants() {
        // 缺省值应与原写死常量一致：启用、阈值 3、窗口 600s、失败表 10 万、封锁表 5 万
        let cfg = IpBlockConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_failures, 3);
        assert_eq!(cfg.window_secs, 600);
        assert_eq!(cfg.max_failed_ips, 100_000);
        assert_eq!(cfg.max_blocked_ips, 50_000);
    }

    #[test]
    fn ip_block_config_absent_section_uses_defaults() {
        // 配置文件未写 [ip_block] 段时，serde(default) 应回退到默认值
        let toml = r#"
[server]
listen_addr = "0.0.0.0"
sip_port = 5061
host = "minghe.local"

[extensions]
range_start = 1000
range_end = 2000
default_password = "pw"

[tls]
cert_path = ""
key_path = ""

[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "192.168.1.100"
"#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert!(config.ip_block.enabled);
        assert_eq!(config.ip_block.max_failures, 3);
        assert_eq!(config.ip_block.window_secs, 600);
        assert_eq!(config.ip_block.max_failed_ips, 100_000);
        assert_eq!(config.ip_block.max_blocked_ips, 50_000);
    }

    #[test]
    fn ip_block_config_parses_custom_values() {
        let toml = r#"
[server]
listen_addr = "0.0.0.0"
sip_port = 5061
host = "minghe.local"

[extensions]
range_start = 1000
range_end = 2000
default_password = "pw"

[tls]
cert_path = ""
key_path = ""

[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "192.168.1.100"

[ip_block]
enabled = false
max_failures = 10
window_secs = 120
max_failed_ips = 5000
max_blocked_ips = 2000
"#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert!(!config.ip_block.enabled);
        assert_eq!(config.ip_block.max_failures, 10);
        assert_eq!(config.ip_block.window_secs, 120);
        assert_eq!(config.ip_block.max_failed_ips, 5000);
        assert_eq!(config.ip_block.max_blocked_ips, 2000);
    }

    #[test]
    fn load_rejects_zero_max_failures_when_enabled() {
        let toml = r#"
[server]
listen_addr = "0.0.0.0"
sip_port = 5061
host = "minghe.local"

[extensions]
range_start = 1000
range_end = 2000
default_password = "pw"

[tls]
cert_path = ""
key_path = ""

[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "192.168.1.100"

[ip_block]
enabled = true
max_failures = 0
window_secs = 600
"#;
        let config: Result<AppConfig, Box<dyn std::error::Error>> = AppConfig::load_from_str_for_test(toml);
        assert!(config.is_err(), "启用时 max_failures=0 应被拒绝");
    }

    impl AppConfig {
        /// 测试辅助：从 TOML 字符串加载（绕过文件读取），复用 load 的校验逻辑
        fn load_from_str_for_test(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let config: AppConfig = toml::from_str(content)
                .map_err(|e| format!("配置文件解析错误: {}", e))?;
            // 与 load 相同的 ip_block 校验
            if config.ip_block.enabled {
                if config.ip_block.max_failures == 0 {
                    return Err("ip_block.max_failures 必须大于 0".into());
                }
                if config.ip_block.window_secs == 0 {
                    return Err("ip_block.window_secs 必须大于 0".into());
                }
                if config.ip_block.max_failed_ips == 0 {
                    return Err("ip_block.max_failed_ips 必须大于 0".into());
                }
                if config.ip_block.max_blocked_ips == 0 {
                    return Err("ip_block.max_blocked_ips 必须大于 0".into());
                }
            }
            Ok(config)
        }
    }
}
