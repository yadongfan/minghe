//! SIP 注册服务模块
//!
//! 管理分机的注册状态，实现 SIP Digest 认证。
//! 支持 REGISTER 请求的完整处理流程：认证挑战 → 验证 → 注册/注销。

use md5::{Digest, Md5};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use super::parser;

/// 注册条目，记录分机的注册信息
#[derive(Debug, Clone)]
pub struct Registration {
    /// 分机号码（字符串形式，如 "1001"）
    pub extension: String,
    /// 联系地址（Contact URI）
    pub contact: String,
    /// 注册过期时间戳（Unix 秒）
    pub expires_at: u64,
    /// 来源传输地址
    pub transport_addr: SocketAddr,
}

/// Digest 认证参数
#[derive(Debug)]
struct DigestParams {
    username: String,
    realm: String,
    nonce: String,
    uri: String,
    response: String,
    /// qop 值（如 "auth"），客户端可能不发送
    qop: Option<String>,
    /// nonce 计数器（十六进制字符串，如 "00000001"）
    nc: Option<String>,
    /// 客户端随机数
    cnonce: Option<String>,
}

/// 注册服务
///
/// 线程安全的内存注册表，处理 REGISTER 请求并实现 Digest 认证。
pub struct RegistrarService {
    /// 分机号码 -> 注册信息的映射
    registrations: RwLock<HashMap<String, Registration>>,
    /// 服务器域名或 IP（用于 Digest realm）
    domain: String,
    /// 所有分机的默认密码
    default_password: String,
    /// 分机独立密码（分机号 -> 密码）
    passwords: HashMap<String, String>,
    /// 分机号码范围
    range_start: u32,
    range_end: u32,
    /// IP 封锁策略（启用开关、阈值、窗口）
    ip_block: IpBlockPolicy,
    /// IP -> 窗口内失败记录（达到阈值后移入封锁表并移除本表条目）
    failed_ips: RwLock<HashMap<String, FailedIpEntry>>,
    /// 已被封锁的 IP（窗口内累计失败达到阈值，进程生命周期内不解封）
    blocked_ips: RwLock<HashSet<String>>,
}

/// 单个 IP 在失败窗口内的计数记录
#[derive(Debug, Clone, Copy)]
struct FailedIpEntry {
    /// 窗口内失败次数
    count: u32,
    /// 窗口起点（Unix 秒），超过窗口自动重置/清理
    window_start: u64,
}

/// 失败计数表（`failed_ips`）默认最大条目数，防止攻击者用海量不同 IP 撑爆内存
const DEFAULT_MAX_FAILED_IPS: usize = 100_000;

/// 封锁表（`blocked_ips`）默认最大条目数，达到上限后不再新增封锁（内存保护，降级为仅告警）
const DEFAULT_MAX_BLOCKED_IPS: usize = 50_000;

/// IP 封锁策略参数（来自配置，而非写死常量）
#[derive(Debug, Clone, Copy)]
pub struct IpBlockPolicy {
    /// 是否启用 IP 封锁
    pub enabled: bool,
    /// 封锁阈值：窗口内累计失败达到该次数即封锁
    pub max_failures: u32,
    /// 失败计数统计窗口（秒）
    pub window_secs: u64,
    /// 失败计数表最大条目数（内存保护上限）
    pub max_failed_ips: usize,
    /// 封锁表最大条目数（内存保护上限，达到后降级为仅告警）
    pub max_blocked_ips: usize,
}

impl Default for IpBlockPolicy {
    /// 默认策略：启用、阈值 3 次、窗口 600s（与原写死常量一致）
    fn default() -> Self {
        Self {
            enabled: true,
            max_failures: 3,
            window_secs: 600,
            max_failed_ips: DEFAULT_MAX_FAILED_IPS,
            max_blocked_ips: DEFAULT_MAX_BLOCKED_IPS,
        }
    }
}

impl IpBlockPolicy {
    /// 以"完全关闭"策略创建（用于无配置的测试场景）
    fn disabled() -> Self {
        Self {
            enabled: false,
            max_failures: u32::MAX,
            window_secs: 600,
            max_failed_ips: DEFAULT_MAX_FAILED_IPS,
            max_blocked_ips: DEFAULT_MAX_BLOCKED_IPS,
        }
    }
}

impl From<&crate::config::IpBlockConfig> for IpBlockPolicy {
    fn from(cfg: &crate::config::IpBlockConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            max_failures: cfg.max_failures,
            window_secs: cfg.window_secs,
            max_failed_ips: cfg.max_failed_ips,
            max_blocked_ips: cfg.max_blocked_ips,
        }
    }
}

/// 当前 Unix 秒
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl RegistrarService {
    /// 创建新的注册服务
    ///
    /// `ip_block` 控制 IP 封锁行为（是否启用、封锁阈值、统计窗口），
    /// 通常由 [crate::config::IpBlockConfig] 转换而来。
    pub fn new(
        domain: String,
        default_password: String,
        passwords: HashMap<String, String>,
        range_start: u32,
        range_end: u32,
        ip_block: IpBlockPolicy,
    ) -> Self {
        if !passwords.is_empty() {
            tracing::info!("已配置 {} 个分机独立密码", passwords.len());
        }
        Self {
            registrations: RwLock::new(HashMap::new()),
            domain,
            default_password,
            passwords,
            range_start,
            range_end,
            ip_block,
            failed_ips: RwLock::new(HashMap::new()),
            blocked_ips: RwLock::new(HashSet::new()),
        }
    }

    /// 检查指定 IP 是否已被封锁
    ///
    /// `pub(crate)`：供 [Router] 在 INVITE 等其它方法上复用同一封锁表。
    /// IP 封锁关闭时始终返回 `false`。
    pub(crate) fn is_blocked(&self, ip: &str) -> bool {
        if !self.ip_block.enabled {
            return false;
        }
        self.blocked_ips.read().unwrap().contains(ip)
    }

    /// 记录一次失败（注册、认证或未认证呼叫探测）；窗口内累计达到阈值后封锁该 IP 并返回 `true`
    ///
    /// 失败计数使用滑动窗口（`ip_block.window_secs`）：窗口外的失败自动过期，
    /// 避免合法用户因历史偶发失败被永久累计误伤。窗口内累计达到阈值后，该 IP
    /// 被移入封锁表（进程生命周期内不解封）。
    ///
    /// IP 封锁关闭（`ip_block.enabled = false`）时，本方法为空操作：不计数、
    /// 不封锁，始终返回 `false`，所有来源均放行进入认证流程。
    ///
    /// 两张表均有容量上限（`ip_block.max_failed_ips` / `ip_block.max_blocked_ips`），防止攻击者
    /// 用海量不同 IP 撑爆内存；达到上限时优先清理过期条目，仍满则清空失败表
    /// 或拒绝新增封锁并告警（降级为仅限流，不崩溃）。
    ///
    /// `pub(crate)`：供 [Router] 在 INVITE 等其它方法上复用同一失败计数。
    pub(crate) fn record_failure(&self, ip: &str) -> bool {
        // IP 封锁关闭：不计数、不封锁，直接放行
        if !self.ip_block.enabled {
            return false;
        }

        let now = now_secs();
        let window_secs = self.ip_block.window_secs;
        let max_failures = self.ip_block.max_failures;
        let max_failed_ips = self.ip_block.max_failed_ips;
        let max_blocked_ips = self.ip_block.max_blocked_ips;
        {
            let mut failed = self.failed_ips.write().unwrap();

            // 容量上限：先清理窗口过期条目，仍超限则清空失败表（丢计数换取内存安全）
            if failed.len() >= max_failed_ips {
                failed.retain(|_, e| now.saturating_sub(e.window_start) < window_secs);
                if failed.len() >= max_failed_ips {
                    tracing::warn!(
                        "failed_ips 表超过上限 ({} 条) 且无过期条目可清理，清空失败表以保护内存",
                        max_failed_ips
                    );
                    failed.clear();
                }
            }

            let entry = failed.entry(ip.to_string()).or_insert(FailedIpEntry {
                count: 0,
                window_start: now,
            });
            // 窗口过期：重置计数，重新开始窗口
            if now.saturating_sub(entry.window_start) >= window_secs {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
            let count = entry.count;

            if count < max_failures {
                tracing::warn!(
                    ip = %ip,
                    "认证/呼叫失败 {}/{}（{}s 窗口内达到 {} 次将封锁）",
                    count,
                    max_failures,
                    window_secs,
                    max_failures
                );
                return false;
            }

            // 达到阈值：移入封锁表（本表条目移除），窗口内单线程已持写锁，无并发丢计数
            failed.remove(ip);
        }

        let mut blocked = self.blocked_ips.write().unwrap();
        if blocked.len() >= max_blocked_ips {
            tracing::warn!(
                ip = %ip,
                "blocked_ips 表已满 ({} 条)，拒绝新增封锁（内存保护降级）",
                max_blocked_ips
            );
            return false;
        }
        blocked.insert(ip.to_string());
        tracing::warn!(
            ip = %ip,
            "认证/呼叫失败累计 {} 次，已永久封锁该 IP",
            max_failures
        );
        true
    }

    /// 清除指定 IP 的失败计数（注册/认证成功时调用，避免合法用户被历史失败累计误伤）
    pub(crate) fn clear_failures(&self, ip: &str) {
        self.failed_ips.write().unwrap().remove(ip);
    }

    /// 获取指定分机的密码
    ///
    /// 优先返回独立密码，未配置则返回默认密码
    fn get_password(&self, extension: &str) -> &str {
        if let Some(pwd) = self.passwords.get(extension) {
            pwd
        } else {
            &self.default_password
        }
    }

    /// 处理 REGISTER 请求
    ///
    /// 完整流程：
    /// 1. 从 To/From URI 提取分机号
    /// 2. 验证分机号在有效范围内
    /// 3. 检查 Authorization 头部
    ///    - 无：返回 401 + WWW-Authenticate 挑战
    ///    - 有：验证 Digest 响应
    ///      - 成功：注册/注销，返回 200 OK
    ///      - 失败：返回 403 Forbidden
    pub fn handle_register(&self, request_text: &str, from_addr: SocketAddr) -> Vec<u8> {
        // 来源 IP（封禁按 IP 维度统计，不含端口）
        let ip = from_addr.ip().to_string();

        // 已被封锁的 IP 直接拒绝，不再进入任何认证流程
        if self.is_blocked(&ip) {
            // 已达封锁阈值的 IP 高频刷请求，若逐条打 WARN 日志会刷屏；
            // 降为 debug（默认日志级别不输出），仅记录一次封锁事件即可。
            tracing::debug!(ip = %ip, "该 IP 已因多次注册失败被封锁，拒绝其 REGISTER 请求");
            return parser::build_response(request_text, 403, "Forbidden");
        }

        // 提取分机号
        let extension = if let Some(uri) = parser::extract_uri_from_header(request_text, "To") {
            parser::extract_extension(&uri)
        } else if let Some(uri) = parser::extract_uri_from_header(request_text, "From") {
            parser::extract_extension(&uri)
        } else {
            None
        };

        let extension = match extension {
            Some(ext) => ext,
            None => {
                tracing::warn!(ip = %ip, "REGISTER 请求缺少有效的分机号");
                self.record_failure(&ip);
                return parser::build_response(request_text, 400, "Bad Request");
            }
        };

        // 验证分机号范围
        let ext_num: u32 = match extension.parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(ip = %ip, "无效的分机号格式: {}", extension);
                self.record_failure(&ip);
                return parser::build_response(request_text, 403, "Forbidden");
            }
        };

        if ext_num < self.range_start || ext_num > self.range_end {
            tracing::warn!(
                ip = %ip,
                "分机号 {} 不在有效范围 {}-{} 内",
                extension,
                self.range_start,
                self.range_end
            );
            self.record_failure(&ip);
            return parser::build_response(request_text, 403, "Forbidden");
        }

        // 检查 Authorization 头部
        let auth_header = parser::extract_header_value(request_text, "Authorization");

        match auth_header {
            None => {
                // 无认证信息，返回 401 挑战
                let nonce = generate_nonce();
                let www_auth = format!(
                    "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"",
                    self.domain, nonce
                );
                tracing::debug!("向分机 {} 发送 Digest 挑战", extension);
                parser::build_response_with_headers(
                    request_text,
                    401,
                    "Unauthorized",
                    &[("WWW-Authenticate", &www_auth)],
                )
            }
            Some(auth_value) => {
                // 解析并验证 Digest 认证
                let params = match parse_authorization(&auth_value) {
                    Some(p) => p,
                    None => {
                        tracing::warn!("无法解析 Authorization 头部: {}", auth_value);
                        return parser::build_response(request_text, 400, "Bad Request");
                    }
                };

                // 获取请求 URI（用于 Digest 计算）
                let _request_uri = parser::extract_request_uri(request_text)
                    .unwrap_or_else(|| format!("sip:{}", self.domain));

                let password = self.get_password(&extension);
                if !validate_digest(
                    &params.username,
                    &params.realm,
                    password,
                    &params.nonce,
                    &params.uri,
                    "REGISTER",
                    &params.response,
                    params.qop.as_deref(),
                    params.nc.as_deref(),
                    params.cnonce.as_deref(),
                ) {
                    tracing::warn!(ip = %ip, "分机 {} 认证失败", extension);
                    self.record_failure(&ip);
                    return parser::build_response(request_text, 403, "Forbidden");
                }

                // 认证成功
                tracing::info!("分机 {} 认证成功（来自 {}）", extension, from_addr);
                // 成功清除该 IP 的失败计数，避免历史偶发失败累计到封锁阈值
                self.clear_failures(&ip);

                // 检查 Expires
                let expires = parser::extract_expires(request_text).unwrap_or(3600);

                if expires == 0 {
                    // 注销
                    self.unregister(&extension);
                    tracing::info!("分机 {} 已注销", extension);
                    return parser::build_response_with_headers(
                        request_text,
                        200,
                        "OK",
                        &[("Expires", "0")],
                    );
                }

                // 注册
                let contact = parser::extract_contact_uri(request_text)
                    .unwrap_or_else(|| format!("sip:{}@{}", extension, from_addr));

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let reg = Registration {
                    extension: extension.clone(),
                    contact: contact.clone(),
                    expires_at: now + expires,
                    transport_addr: from_addr,
                };

                self.register(reg);

                let contact_header = format!("<{}>;expires={}", contact, expires);
                parser::build_response_with_headers(
                    request_text,
                    200,
                    "OK",
                    &[
                        ("Contact", &contact_header),
                        ("Expires", &expires.to_string()),
                    ],
                )
            }
        }
    }

    /// 注册或更新分机
    ///
    /// `pub(crate)`：供本 crate 测试直接注入注册条目（生产路径由 [handle_register] 调用）。
    pub(crate) fn register(&self, reg: Registration) {
        let ext = reg.extension.clone();
        let mut map = self.registrations.write().unwrap();
        tracing::info!("分机 {} 注册成功，联系地址: {}", ext, reg.contact);
        map.insert(ext, reg);
    }

    /// 注销分机
    pub fn unregister(&self, extension: &str) {
        let mut map = self.registrations.write().unwrap();
        if map.remove(extension).is_some() {
            tracing::info!("分机 {} 已注销", extension);
        }
    }

    /// 查找分机的注册信息
    pub fn lookup(&self, extension: &str) -> Option<Registration> {
        let map = self.registrations.read().unwrap();
        let reg = map.get(extension)?;
        // 检查是否过期
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if reg.expires_at > now {
            Some(reg.clone())
        } else {
            None
        }
    }

    /// 检查分机是否在线（已注册且未过期）
    pub fn is_registered(&self, extension: &str) -> bool {
        self.lookup(extension).is_some()
    }

    /// 获取当前在线分机数量
    pub fn online_count(&self) -> usize {
        let map = self.registrations.read().unwrap();
        map.len()
    }

    /// 清理过期的注册
    pub fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut map = self.registrations.write().unwrap();
        let before = map.len();
        map.retain(|ext, reg| {
            if reg.expires_at <= now {
                tracing::debug!("分机 {} 注册已过期，自动清理", ext);
                false
            } else {
                true
            }
        });
        let removed = before - map.len();
        if removed > 0 {
            tracing::info!("清理了 {} 个过期注册", removed);
        }
    }

    /// 启动后台清理任务
    pub fn start_cleanup_task(self: &Arc<Self>) {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                svc.cleanup_expired();
            }
        });
    }
}

// ============================================================
// Digest 认证辅助函数
// ============================================================

/// 生成随机 nonce（32 字节十六进制字符串）
fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// 解析 Authorization 头部值
///
/// 输入格式：`Digest username="1001", realm="minghe.local", nonce="xxx", uri="sip:minghe.local", response="yyy"`
fn parse_authorization(header_value: &str) -> Option<DigestParams> {
    let value = header_value.trim();
    let value = if let Some(rest) = value.strip_prefix("Digest") {
        rest.trim()
    } else {
        value
    };

    let mut username = String::new();
    let mut realm = String::new();
    let mut nonce = String::new();
    let mut uri = String::new();
    let mut response = String::new();
    let mut qop: Option<String> = None;
    let mut nc: Option<String> = None;
    let mut cnonce: Option<String> = None;

    // 解析 key="value" 对
    // 需要处理值中可能包含逗号的情况（如 URI）
    for param in split_digest_params(value) {
        let param = param.trim();
        if let Some((key, val)) = param.split_once('=') {
            let key = key.trim().to_lowercase();
            let val = val.trim().trim_matches('"').to_string();
            match key.as_str() {
                "username" => username = val,
                "realm" => realm = val,
                "nonce" => nonce = val,
                "uri" => uri = val,
                "response" => response = val,
                "qop" => qop = Some(val),
                "nc" => nc = Some(val),
                "cnonce" => cnonce = Some(val),
                _ => {} // 忽略其他参数 (algorithm 等)
            }
        }
    }

    if username.is_empty() || nonce.is_empty() || response.is_empty() {
        return None;
    }

    Some(DigestParams {
        username,
        realm,
        nonce,
        uri,
        response,
        qop,
        nc,
        cnonce,
    })
}

/// 分割 Digest 参数（处理引号内的逗号）
fn split_digest_params(input: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    params.push(current.clone());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        params.push(current);
    }
    params
}

/// 验证 Digest 认证响应
///
/// 支持两种算法：
/// - RFC 2069（无 qop）：response = MD5(HA1:nonce:HA2)
/// - RFC 2617（qop=auth）：response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
///
/// ```text
/// HA1 = MD5(username:realm:password)
/// HA2 = MD5(method:uri)
/// ```
fn validate_digest(
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    uri: &str,
    method: &str,
    response: &str,
    qop: Option<&str>,
    nc: Option<&str>,
    cnonce: Option<&str>,
) -> bool {
    let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, password));
    let ha2 = md5_hex(&format!("{}:{}", method, uri));

    let expected = match qop {
        Some("auth") => {
            // RFC 2617 qop=auth: response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            let nc = nc.unwrap_or("00000001");
            let cnonce = cnonce.unwrap_or("");
            md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2))
        }
        _ => {
            // RFC 2069（无 qop）：response = MD5(HA1:nonce:HA2)
            md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2))
        }
    };

    tracing::debug!(
        "Digest 验证: username={}, realm={}, qop={:?}, HA1={}, HA2={}, expected={}, received={}",
        username,
        realm,
        qop,
        ha1,
        ha2,
        expected,
        response
    );

    expected.to_lowercase() == response.to_lowercase()
}

/// 计算 MD5 哈希并返回小写十六进制字符串
fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_hex() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_digest_validation_no_qop() {
        // RFC 2069（无 qop）:
        // HA1 = MD5("1001:minghe.local:minghe@2024")
        // HA2 = MD5("REGISTER:sip:minghe.local")
        // expected = MD5(HA1:testnonce:HA2)
        let ha1 = md5_hex("1001:minghe.local:minghe@2024");
        let ha2 = md5_hex("REGISTER:sip:minghe.local");
        let response = md5_hex(&format!("{}:testnonce:{}", ha1, ha2));

        assert!(validate_digest(
            "1001",
            "minghe.local",
            "minghe@2024",
            "testnonce",
            "sip:minghe.local",
            "REGISTER",
            &response,
            None,
            None,
            None,
        ));
    }

    #[test]
    fn test_digest_validation_qop_auth() {
        // RFC 2617（qop=auth）:
        // response = MD5(HA1:nonce:nc:cnonce:auth:HA2)
        let ha1 = md5_hex("1001:minghe.local:minghe@2024");
        let ha2 = md5_hex("REGISTER:sip:minghe.local");
        let response = md5_hex(&format!(
            "{}:testnonce:00000001:clientnonce:auth:{}",
            ha1, ha2
        ));

        assert!(validate_digest(
            "1001",
            "minghe.local",
            "minghe@2024",
            "testnonce",
            "sip:minghe.local",
            "REGISTER",
            &response,
            Some("auth"),
            Some("00000001"),
            Some("clientnonce"),
        ));
    }

    #[test]
    fn test_digest_validation_wrong_password() {
        let ha1 = md5_hex("1001:minghe.local:wrongpassword");
        let ha2 = md5_hex("REGISTER:sip:minghe.local");
        let response = md5_hex(&format!("{}:testnonce:{}", ha1, ha2));

        assert!(!validate_digest(
            "1001",
            "minghe.local",
            "minghe@2024",
            "testnonce",
            "sip:minghe.local",
            "REGISTER",
            &response,
            None,
            None,
            None,
        ));
    }

    #[test]
    fn test_parse_authorization() {
        let header = r#"Digest username="1001", realm="minghe.local", nonce="abc123", uri="sip:minghe.local", response="deadbeef""#;
        let params = parse_authorization(header).unwrap();
        assert_eq!(params.username, "1001");
        assert_eq!(params.realm, "minghe.local");
        assert_eq!(params.nonce, "abc123");
        assert_eq!(params.uri, "sip:minghe.local");
        assert_eq!(params.response, "deadbeef");
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32); // 16 bytes = 32 hex chars
    }

    /// 构造一条面向 example.com 的 REGISTER 请求
    fn register_request(ext: &str, call_id: &str, auth_header: &str) -> String {
        format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS 127.0.0.1:6060;branch=z9hG4bK{0}\r\n\
             From: <sip:{1}@example.com>;tag=tag-{0}\r\n\
             To: <sip:{1}@example.com>\r\n\
             Call-ID: {0}\r\n\
             CSeq: 1 REGISTER\r\n\
             {2}Contact: <sip:{1}@127.0.0.1:6060;transport=tls>\r\n\
             Expires: 300\r\n\
             Content-Length: 0\r\n\r\n",
            call_id, ext, auth_header
        )
    }

    #[test]
    fn ip_blocked_after_three_register_failures() {
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy::default(),
        );
        let from: SocketAddr = "203.0.113.9:5061".parse().unwrap();

        // 连续 3 次请求范围外分机（攻击者典型行为）→ 第 3 次后应封锁
        for i in 0..3 {
            let resp = registrar.handle_register(
                &register_request("80001", &format!("fail-{}", i), ""),
                from,
            );
            assert_eq!(
                parser::extract_status_code(&String::from_utf8(resp).unwrap()),
                Some(403)
            );
        }
        assert!(registrar.is_blocked("203.0.113.9"));

        // 封锁后，合法分机也被同 IP 拒绝
        for i in 0..2 {
            let resp = registrar.handle_register(
                &register_request("1001", &format!("blocked-{}", i), ""),
                from,
            );
            assert_eq!(
                parser::extract_status_code(&String::from_utf8(resp).unwrap()),
                Some(403)
            );
        }
        assert!(!registrar.is_registered("1001"));

        // 其他 IP 不受影响，仍可获得 401 挑战
        let other: SocketAddr = "198.51.100.7:5061".parse().unwrap();
        let resp = registrar.handle_register(
            &register_request("1001", "other-ip", ""),
            other,
        );
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 401 Unauthorized"));
    }

    #[test]
    fn ip_block_counts_by_ip_regardless_of_port() {
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy::default(),
        );
        // 同一 IP 不同端口（攻击者高频换端口）累计失败同样封禁该 IP
        for port in [5061u16, 5300, 5500] {
            let from: SocketAddr = format!("203.0.113.20:{}", port).parse().unwrap();
            let resp = registrar.handle_register(
                &register_request("99999", &format!("port-{}", port), ""),
                from,
            );
            // 请求范围外分机应被拒绝 403 并计入该 IP 失败
            assert_eq!(
                parser::extract_status_code(&String::from_utf8(resp).unwrap()),
                Some(403)
            );
        }
        // 三次失败（三个不同端口）来自同一 IP → 应已封锁
        assert!(registrar.is_blocked("203.0.113.20"));
    }

    #[test]
    fn successful_register_clears_failed_count() {
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy::default(),
        );
        let from: SocketAddr = "203.0.113.30:5061".parse().unwrap();

        // 2 次失败（未达阈值），随后一次合法 REGISTER 认证成功
        for i in 0..2 {
            let resp = registrar.handle_register(
                &register_request("80001", &format!("fail-{}", i), ""),
                from,
            );
            assert_eq!(
                parser::extract_status_code(&String::from_utf8(resp).unwrap()),
                Some(403)
            );
        }
        // 成功认证：Digest 响应正确，应返回 200 并清除该 IP 失败计数
        let ha1 = md5_hex("1001:example.com:pw");
        let ha2 = md5_hex("REGISTER:sip:example.com");
        let response = md5_hex(&format!("{}:testnonce:{}", ha1, ha2));
        let auth = format!(
            "Authorization: Digest username=\"1001\", realm=\"example.com\", nonce=\"testnonce\", uri=\"sip:example.com\", response=\"{}\"\r\n",
            response
        );
        let resp = registrar.handle_register(&register_request("1001", "ok", &auth), from);
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 200 OK"));
        assert!(!registrar.is_blocked("203.0.113.30"));

        // 清除后重新失败：累计 2 次不封锁，第 3 次才封锁（证明计数已被重置）
        for i in 0..2 {
            let resp = registrar.handle_register(
                &register_request("80002", &format!("fail2-{}", i), ""),
                from,
            );
            let _ = resp;
        }
        assert!(!registrar.is_blocked("203.0.113.30"), "失败计数应已重置");
        let resp = registrar.handle_register(
            &register_request("80003", "fail3", ""),
            from,
        );
        let _ = resp;
        assert!(registrar.is_blocked("203.0.113.30"), "重置后第 3 次失败应封锁");
    }

    #[test]
    fn failures_expire_after_window_without_blocking() {
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy::default(),
        );
        // 2 次失败（count=2），随后直接把窗口起点拨到窗口外
        for i in 0..2 {
            registrar.record_failure("203.0.113.40");
            let _ = i;
        }
        {
            let mut failed = registrar.failed_ips.write().unwrap();
            if let Some(entry) = failed.get_mut("203.0.113.40") {
                entry.window_start =
                    now_secs().saturating_sub(registrar.ip_block.window_secs + 1);
            }
        }
        // 窗口外的历史失败不参与累计：再失败 2 次也不应封锁
        assert!(!registrar.record_failure("203.0.113.40"));
        assert!(!registrar.record_failure("203.0.113.40"));
        assert!(!registrar.is_blocked("203.0.113.40"));
    }

    #[test]
    fn failed_table_respects_capacity_cap() {
        // 用小容量验证失败表上限保护（避免填满 10 万条）
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                enabled: true,
                max_failures: 3,
                window_secs: 600,
                max_failed_ips: 4,
                max_blocked_ips: 50_000,
            },
        );
        // 填满失败表（模拟扫描器海量不同 IP）
        let now = now_secs();
        let cap = registrar.ip_block.max_failed_ips;
        {
            let mut failed = registrar.failed_ips.write().unwrap();
            for i in 0..cap {
                failed.insert(
                    format!("198.51.{}.{}", (i >> 8) % 256, i % 256),
                    FailedIpEntry {
                        count: 1,
                        window_start: now,
                    },
                );
            }
        }
        // 表已满且无过期条目：record_failure 应清空表并正常计数，不死锁/不 panic
        assert!(!registrar.record_failure("203.0.113.50"));
        let len = registrar.failed_ips.read().unwrap().len();
        assert!(len < cap, "超限后应清理失败表, got {len}");
        // 清理后新 IP 仍能正常累计并封锁
        for _ in 0..2 {
            registrar.record_failure("203.0.113.50");
        }
        assert!(registrar.is_blocked("203.0.113.50"));
    }

    #[test]
    fn blocked_table_respects_capacity_cap() {
        // 用小容量验证封锁表上限保护（避免填满 5 万条）
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                enabled: true,
                max_failures: 3,
                window_secs: 600,
                max_failed_ips: 100_000,
                max_blocked_ips: 4,
            },
        );
        // 直接填满封锁表
        let cap = registrar.ip_block.max_blocked_ips;
        {
            let mut blocked = registrar.blocked_ips.write().unwrap();
            for i in 0..cap {
                blocked.insert(format!("198.51.{}.{}", (i >> 8) % 256, i % 256));
            }
        }
        // 表满后新增封锁被拒绝（内存保护降级），不 panic
        assert!(!registrar.record_failure("203.0.113.60"));
        assert!(!registrar.is_blocked("203.0.113.60"));
    }

    #[test]
    fn ip_block_disabled_never_blocks_or_counts() {
        // 关闭 IP 封锁：无论失败多少次都不应封锁，也不累计计数
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy::disabled(),
        );
        for _ in 0..100 {
            assert!(!registrar.record_failure("203.0.113.77"));
        }
        assert!(!registrar.is_blocked("203.0.113.77"));
        // 失败表不应产生任何条目（record_failure 在禁用时直接返回）
        assert!(registrar.failed_ips.read().unwrap().is_empty());

        // 禁用状态下，is_blocked 对已手动写入封锁表的 IP 也返回 false
        {
            registrar
                .blocked_ips
                .write()
                .unwrap()
                .insert("203.0.113.77".to_string());
        }
        assert!(!registrar.is_blocked("203.0.113.77"));
    }

    #[test]
    fn ip_block_respects_custom_threshold() {
        // 自定义阈值 5 次：前 4 次不封锁，第 5 次封锁
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                enabled: true,
                max_failures: 5,
                window_secs: 600,
                max_failed_ips: 100_000,
                max_blocked_ips: 50_000,
            },
        );
        for _ in 0..4 {
            assert!(!registrar.record_failure("203.0.113.88"));
        }
        assert!(!registrar.is_blocked("203.0.113.88"), "4 次失败不应封锁");
        assert!(registrar.record_failure("203.0.113.88"), "第 5 次失败应触发封锁");
        assert!(registrar.is_blocked("203.0.113.88"));
    }

    #[test]
    fn ip_block_respects_custom_window() {
        // 自定义窗口 60s：把窗口起点拨到 61s 前应使历史失败过期
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                enabled: true,
                max_failures: 3,
                window_secs: 60,
                max_failed_ips: 100_000,
                max_blocked_ips: 50_000,
            },
        );
        // 2 次失败后拨到窗口外
        for _ in 0..2 {
            registrar.record_failure("203.0.113.99");
        }
        {
            let mut failed = registrar.failed_ips.write().unwrap();
            if let Some(entry) = failed.get_mut("203.0.113.99") {
                entry.window_start = now_secs().saturating_sub(registrar.ip_block.window_secs + 1);
            }
        }
        // 窗口外的历史失败不参与累计：再失败 2 次也不应封锁
        assert!(!registrar.record_failure("203.0.113.99"));
        assert!(!registrar.record_failure("203.0.113.99"));
        assert!(!registrar.is_blocked("203.0.113.99"));
    }
}
