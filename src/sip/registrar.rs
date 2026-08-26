//! SIP 注册服务模块
//!
//! 管理分机的注册状态，实现 SIP Digest 认证。
//! 支持 REGISTER 请求的完整处理流程：认证挑战 → 验证 → 注册/注销。

use ipnet::IpNet;
use md5::{Digest, Md5};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
    /// 已被封锁的 IP -> 封锁到期时间戳与等级（临时封锁 + 递增退避，到期自动解封）
    blocked_ips: RwLock<HashMap<String, BlockedEntry>>,
    /// 各 IP 最近一次封锁等级（解封后再触顶时递增；认证成功时重置）
    ban_levels: RwLock<HashMap<String, u32>>,
    /// 未认证 INVITE 限速计数表：IP -> 窗口内未认证 INVITE 次数
    invite_counts: RwLock<HashMap<String, InviteCountEntry>>,
    /// 未认证 INVITE 限速冷却表：IP -> 冷却到期时间戳（冷却期内直接拒绝）
    invite_cooldowns: RwLock<HashMap<String, u64>>,
}

/// 单个 IP 在失败窗口内的计数记录
#[derive(Debug, Clone, Copy)]
struct FailedIpEntry {
    /// 窗口内失败次数
    count: u32,
    /// 窗口起点（Unix 秒），超过窗口自动重置/清理
    window_start: u64,
}

/// 单个 IP 在未认证 INVITE 限速窗口内的计数记录
#[derive(Debug, Clone, Copy)]
struct InviteCountEntry {
    /// 窗口内未认证 INVITE 次数
    count: u32,
    /// 窗口起点（Unix 秒），超过窗口自动重置/清理
    window_start: u64,
}

/// 封锁表条目：记录封锁到期时间与当前退避等级
#[derive(Debug, Clone, Copy)]
struct BlockedEntry {
    /// 封锁到期时间戳（Unix 秒），`now < until` 时该 IP 视为被封锁
    until: u64,
    /// 当前退避等级（第 n 次封锁），决定本次封锁时长
    level: u32,
}

/// 失败计数表（`failed_ips`）默认最大条目数，防止攻击者用海量不同 IP 撑爆内存
const DEFAULT_MAX_FAILED_IPS: usize = 100_000;

/// 封锁表（`blocked_ips`）默认最大条目数，达到上限后不再新增封锁（内存保护，降级为仅告警）
const DEFAULT_MAX_BLOCKED_IPS: usize = 50_000;

/// IP 封锁策略参数（来自配置，而非写死常量）
#[derive(Debug, Clone)]
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
    /// 未认证 INVITE 限速阈值（每 `invite_window_secs` 窗口）
    pub invite_limit: u32,
    /// 未认证 INVITE 限速统计窗口（秒）
    pub invite_window_secs: u64,
    /// 未认证 INVITE 触发限速后的冷却时长（秒）
    pub invite_cooldown_secs: u64,
    /// 退避初始时长（秒）：第 1 次封锁持续该时长
    pub ban_base_secs: u64,
    /// 退避递增倍率：第 n 次封锁时长 = `ban_base_secs * ban_factor^(n-1)`（封顶于 `max_ban_secs`）
    pub ban_factor: u32,
    /// 退避封顶时长（秒）：封锁时长上限，可配到天级（如 30 天 = `2592000`）
    pub max_ban_secs: u64,
    /// 白名单（可信 IP / CIDR 网段）：命中不计数、不封锁、不限速
    pub whitelist: Vec<IpNet>,
}

impl Default for IpBlockPolicy {
    /// 默认策略：启用、阈值 5 次、窗口 600s（与 IpBlockConfig 默认一致）
    fn default() -> Self {
        Self {
            enabled: true,
            max_failures: 5,
            window_secs: 600,
            max_failed_ips: DEFAULT_MAX_FAILED_IPS,
            max_blocked_ips: DEFAULT_MAX_BLOCKED_IPS,
            invite_limit: 10,
            invite_window_secs: 60,
            invite_cooldown_secs: 60,
            ban_base_secs: 60,
            ban_factor: 10,
            max_ban_secs: 3600,
            whitelist: Vec::new(),
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
            invite_limit: u32::MAX,
            invite_window_secs: 60,
            invite_cooldown_secs: 60,
            ban_base_secs: 60,
            ban_factor: 10,
            max_ban_secs: 3600,
            whitelist: Vec::new(),
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
            invite_limit: cfg.invite_limit,
            invite_window_secs: cfg.invite_window_secs,
            invite_cooldown_secs: cfg.invite_cooldown_secs,
            ban_base_secs: cfg.ban_base_secs,
            ban_factor: cfg.ban_factor,
            max_ban_secs: cfg.max_ban_secs,
            whitelist: parse_whitelist(&cfg.whitelist),
        }
    }
}

/// 把白名单字符串列表解析为 [IpNet]（纯 IP 视为全位主机；配置加载时已校验合法）
fn parse_whitelist(items: &[String]) -> Vec<IpNet> {
    items
        .iter()
        .filter_map(|s| {
            s.parse::<IpNet>().ok().or_else(|| {
                s.parse::<IpAddr>().ok().and_then(|addr| {
                    let prefix = if addr.is_ipv4() { 32 } else { 128 };
                    IpNet::new(addr, prefix).ok()
                })
            })
        })
        .collect()
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
            blocked_ips: RwLock::new(HashMap::new()),
            ban_levels: RwLock::new(HashMap::new()),
            invite_counts: RwLock::new(HashMap::new()),
            invite_cooldowns: RwLock::new(HashMap::new()),
        }
    }

    /// 判断来源 IP 是否命中白名单（可信 IP / CIDR 网段）
    ///
    /// 命中白名单的来源不计数、不封锁、不限速。IP 无法解析时视为未命中。
    fn is_whitelisted(&self, ip: &str) -> bool {
        if self.ip_block.whitelist.is_empty() {
            return false;
        }
        let Ok(addr) = ip.parse::<IpAddr>() else {
            return false;
        };
        self.ip_block.whitelist.iter().any(|net| net.contains(&addr))
    }

    /// 检查指定 IP 是否已被封锁
    ///
    /// `pub(crate)`：供 [Router] 在 INVITE 等其它方法上复用同一封锁表。
    /// IP 封锁关闭或命中白名单时始终返回 `false`。
    ///
    /// 临时封锁：`blocked_ips` 记录到期时间戳，未到期返回 `true`；到期则懒清理
    /// （移除条目并把等级写回 `ban_levels`，供解封后再触顶时递增），返回 `false`。
    pub(crate) fn is_blocked(&self, ip: &str) -> bool {
        if !self.ip_block.enabled || self.is_whitelisted(ip) {
            return false;
        }
        let now = now_secs();
        let mut blocked = self.blocked_ips.write().unwrap();
        match blocked.get(ip) {
            Some(entry) if now < entry.until => true,
            Some(entry) => {
                // 封锁到期：懒清理，保留等级供下次递增
                let level = entry.level;
                blocked.remove(ip);
                drop(blocked);
                self.ban_levels.write().unwrap().insert(ip.to_string(), level);
                false
            }
            None => false,
        }
    }

    /// 记录一次失败（注册、认证或未认证呼叫探测）；窗口内累计达到阈值后封锁该 IP 并返回 `true`
    ///
    /// 失败计数使用滑动窗口（`ip_block.window_secs`）：窗口外的失败自动过期，
    /// 避免合法用户因历史偶发失败被永久累计误伤。窗口内累计达到阈值后，该 IP
    /// 被移入封锁表（临时封锁 + 递增退避，`ban_base_secs * ban_factor^(n-1)`，封顶于
    /// `max_ban_secs`），到期自动解封。
    ///
    /// IP 封锁关闭（`ip_block.enabled = false`）或命中白名单时，本方法为空操作：
    /// 不计数、不封锁，始终返回 `false`，所有来源均放行进入认证流程。
    ///
    /// 两张表均有容量上限（`ip_block.max_failed_ips` / `ip_block.max_blocked_ips`），防止攻击者
    /// 用海量不同 IP 撑爆内存；达到上限时优先清理过期条目，仍满则清空失败表
    /// 或拒绝新增封锁并告警（降级为仅限流，不崩溃）。退避封锁因到期自动回收，
    /// 封锁表在持续分布式攻击下不会像永久封锁那样累积到上限后整体失效。
    ///
    /// `pub(crate)`：供 [Router] 在 INVITE 等其它方法上复用同一失败计数。
    pub(crate) fn record_failure(&self, ip: &str) -> bool {
        // IP 封锁关闭或命中白名单：不计数、不封锁，直接放行
        if !self.ip_block.enabled || self.is_whitelisted(ip) {
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

            // 达到阈值：计算退避时长并移入封锁表（本表条目移除），窗口内单线程已持写锁，无并发丢计数
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
        // 递增退避：上次封锁等级 +1，时长按 base * factor^(level-1) 递增，封顶于 max_ban_secs
        let level = {
            let levels = self.ban_levels.read().unwrap();
            levels.get(ip).copied().unwrap_or(0) + 1
        };
        let duration = self.ban_duration(level);
        blocked.insert(
            ip.to_string(),
            BlockedEntry {
                until: now.saturating_add(duration),
                level,
            },
        );
        drop(blocked);
        let mut levels = self.ban_levels.write().unwrap();
        // 等级表容量上限（复用 max_blocked_ips）：满则清空，下次封锁从等级 1 重新开始（内存保护）
        if levels.len() >= max_blocked_ips {
            tracing::warn!(
                "ban_levels 表超过上限 ({} 条)，清空以保护内存（下次封锁从等级 1 重新开始）",
                max_blocked_ips
            );
            levels.clear();
        }
        levels.insert(ip.to_string(), level);
        tracing::warn!(
            ip = %ip,
            "认证/呼叫失败累计 {} 次，封锁 {}s（退避等级 {}，封顶 {}s）",
            max_failures,
            duration,
            level,
            self.ip_block.max_ban_secs
        );
        true
    }

    /// 计算第 `level` 次封锁的时长（递增退避，封顶于 `max_ban_secs`）
    fn ban_duration(&self, level: u32) -> u64 {
        let base = self.ip_block.ban_base_secs;
        let factor = self.ip_block.ban_factor.max(1) as u64;
        let max = self.ip_block.max_ban_secs;
        let mut dur = base;
        if factor > 1 {
            for _ in 1..level {
                if dur >= max {
                    break;
                }
                dur = dur.saturating_mul(factor);
                if dur > max {
                    dur = max;
                }
            }
        }
        dur.min(max)
    }

    /// 清除指定 IP 的失败计数（注册/认证成功时调用，避免合法用户被历史失败累计误伤）
    ///
    /// 同时重置退避等级；若该 IP 处于封锁中则一并解除（认证成功提前解封）。
    pub(crate) fn clear_failures(&self, ip: &str) {
        self.failed_ips.write().unwrap().remove(ip);
        self.unblock(ip);
    }

    /// 立即解除指定 IP 的封锁并重置退避等级（认证成功提前解封；对未封锁 IP 为空操作）
    pub(crate) fn unblock(&self, ip: &str) {
        self.blocked_ips.write().unwrap().remove(ip);
        self.ban_levels.write().unwrap().remove(ip);
    }

    /// 检查指定 IP 是否处于未认证 INVITE 限速冷却期
    ///
    /// 冷却期内未认证 INVITE 直接拒绝（不重复计数）。与封锁表完全隔离：
    /// 未认证 INVITE 不会触发 IP 封锁，攻击者无需猜密码即可触发封锁的问题由此消除。
    ///
    /// IP 封锁关闭（`ip_block.enabled = false`）或命中白名单时始终返回 `false`（不限速）。
    pub(crate) fn is_invite_limited(&self, ip: &str) -> bool {
        if !self.ip_block.enabled || self.is_whitelisted(ip) {
            return false;
        }
        let now = now_secs();
        let mut cooldowns = self.invite_cooldowns.write().unwrap();
        match cooldowns.get(ip) {
            Some(&until) if now < until => true,
            // 冷却到期：懒清理
            Some(_) => {
                cooldowns.remove(ip);
                false
            }
            None => false,
        }
    }

    /// 记录一次未认证 INVITE；窗口内达到限速阈值后进入冷却期
    ///
    /// 与 [record_failure] 独立：未认证 INVITE 走滑动窗口限速（`invite_limit` 次 /
    /// `invite_window_secs`），触发后冷却 `invite_cooldown_secs` 秒，不进入封锁表。
    ///
    /// IP 封锁关闭（`ip_block.enabled = false`）或命中白名单时为空操作。
    pub(crate) fn record_unauthed_invite(&self, ip: &str) {
        if !self.ip_block.enabled || self.is_whitelisted(ip) {
            return;
        }
        // 已在冷却期：不重复计数
        if self.is_invite_limited(ip) {
            return;
        }

        let now = now_secs();
        let window_secs = self.ip_block.invite_window_secs;
        let limit = self.ip_block.invite_limit;
        let cooldown_secs = self.ip_block.invite_cooldown_secs;
        let max_counts = self.ip_block.max_failed_ips;
        let max_cooldowns = self.ip_block.max_blocked_ips;

        let mut counts = self.invite_counts.write().unwrap();
        // 容量上限：先清理窗口过期条目，仍超限则清空（丢计数换取内存安全，与 failed_ips 一致）
        if counts.len() >= max_counts {
            counts.retain(|_, e| now.saturating_sub(e.window_start) < window_secs);
            if counts.len() >= max_counts {
                tracing::warn!(
                    "invite_counts 表超过上限 ({} 条)，清空以保护内存",
                    max_counts
                );
                counts.clear();
            }
        }
        let entry = counts.entry(ip.to_string()).or_insert(InviteCountEntry {
            count: 0,
            window_start: now,
        });
        // 窗口过期：重置计数，重新开始窗口
        if now.saturating_sub(entry.window_start) >= window_secs {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;

        if entry.count < limit {
            tracing::debug!(
                ip = %ip,
                "未认证 INVITE {}/{}（{}s 窗口内达到 {} 次将限速 {}s）",
                entry.count,
                limit,
                window_secs,
                limit,
                cooldown_secs
            );
            return;
        }

        // 达到限速阈值：进入冷却并清空窗口计数
        counts.remove(ip);
        drop(counts);
        let mut cooldowns = self.invite_cooldowns.write().unwrap();
        // 冷却表容量上限（复用 max_blocked_ips）：先清理已到期条目，仍满则拒绝新增冷却（降级）
        if cooldowns.len() >= max_cooldowns {
            cooldowns.retain(|_, until| now < *until);
            if cooldowns.len() >= max_cooldowns {
                tracing::warn!(
                    "invite_cooldowns 表已满 ({} 条)，拒绝新增冷却（内存保护降级）",
                    max_cooldowns
                );
                return;
            }
        }
        cooldowns.insert(ip.to_string(), now + cooldown_secs);
        tracing::warn!(
            ip = %ip,
            "未认证 INVITE 窗口内达到 {} 次，限速 {}s（不进入封锁表）",
            limit,
            cooldown_secs
        );
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

        // 已被封锁的 IP：携带 Authorization 的请求放行进入认证流程尝试自救
        // （认证成功即解封，见下方认证成功分支）；无凭据直接拒绝。
        // 封锁期内认证失败不再计入失败计数（不刷新/延长封锁），否则攻击者可用
        // 任意错误凭据持续请求让封锁永不到期、退避等级无界增长。
        let ip_blocked = self.is_blocked(&ip);
        if ip_blocked {
            let has_auth = parser::extract_header_value(request_text, "Authorization").is_some();
            if !has_auth {
                // 已达封锁阈值的 IP 高频刷请求，若逐条打 WARN 日志会刷屏；
                // 降为 debug（默认日志级别不输出），仅记录一次封锁事件即可。
                tracing::debug!(ip = %ip, "该 IP 已被封锁且无认证凭据，拒绝其 REGISTER 请求");
                return parser::build_response(request_text, 403, "Forbidden");
            }
            tracing::info!(
                ip = %ip,
                "该 IP 已被封锁，请求携带认证凭据，尝试认证自救（成功即解封）"
            );
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
                if !ip_blocked {
                    self.record_failure(&ip);
                }
                return parser::build_response(request_text, 400, "Bad Request");
            }
        };

        // 验证分机号范围
        let ext_num: u32 = match extension.parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(ip = %ip, "无效的分机号格式: {}", extension);
                if !ip_blocked {
                    self.record_failure(&ip);
                }
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
            if !ip_blocked {
                self.record_failure(&ip);
            }
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
                    if !ip_blocked {
                        self.record_failure(&ip);
                    }
                    return parser::build_response(request_text, 403, "Forbidden");
                }

                // 认证成功
                tracing::info!("分机 {} 认证成功（来自 {}）", extension, from_addr);
                // 成功清除该 IP 的失败计数与退避等级；若该 IP 处于封锁中则提前解封
                //（认证成功提前解封，真实用户输对一次密码即可自救，攻击者无凭据无法利用）
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
            IpBlockPolicy {
                enabled: true,
                max_failures: 3,
                window_secs: 600,
                max_failed_ips: 100_000,
                max_blocked_ips: 50_000,
                invite_limit: 10,
                invite_window_secs: 60,
                invite_cooldown_secs: 60,
                ban_base_secs: 60,
                ban_factor: 10,
                max_ban_secs: 3600,
                whitelist: Vec::new(),
            },
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
        // 默认阈值为 5：5 次失败（不同端口）来自同一 IP → 应已封锁
        for port in [5061u16, 5300, 5500, 5700, 5900] {
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
        // 5 次失败（五个不同端口）来自同一 IP → 应已封锁
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

        // 清除后重新失败：默认阈值 5，累计 4 次不封锁，第 5 次才封锁（证明计数已被重置）
        for i in 0..4 {
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
        assert!(registrar.is_blocked("203.0.113.30"), "重置后第 5 次失败应封锁");
    }

    #[test]
    fn failures_expire_after_window_without_blocking() {
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
                max_blocked_ips: 50_000,
                invite_limit: 10,
                invite_window_secs: 60,
                invite_cooldown_secs: 60,
                ban_base_secs: 60,
                ban_factor: 10,
                max_ban_secs: 3600,
                whitelist: Vec::new(),
            },
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
                invite_limit: 10,
                invite_window_secs: 60,
                invite_cooldown_secs: 60,
                ban_base_secs: 60,
                ban_factor: 10,
                max_ban_secs: 3600,
                whitelist: Vec::new(),
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
                invite_limit: 10,
                invite_window_secs: 60,
                invite_cooldown_secs: 60,
                ban_base_secs: 60,
                ban_factor: 10,
                max_ban_secs: 3600,
                whitelist: Vec::new(),
            },
        );
        // 直接填满封锁表
        let cap = registrar.ip_block.max_blocked_ips;
        {
            let mut blocked = registrar.blocked_ips.write().unwrap();
            for i in 0..cap {
                blocked.insert(
                    format!("198.51.{}.{}", (i >> 8) % 256, i % 256),
                    BlockedEntry {
                        until: u64::MAX,
                        level: 1,
                    },
                );
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
                .insert(
                    "203.0.113.77".to_string(),
                    BlockedEntry {
                        until: u64::MAX,
                        level: 1,
                    },
                );
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
                invite_limit: 10,
                invite_window_secs: 60,
                invite_cooldown_secs: 60,
                ban_base_secs: 60,
                ban_factor: 10,
                max_ban_secs: 3600,
                whitelist: Vec::new(),
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
                invite_limit: 10,
                invite_window_secs: 60,
                invite_cooldown_secs: 60,
                ban_base_secs: 60,
                ban_factor: 10,
                max_ban_secs: 3600,
                whitelist: Vec::new(),
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

    /// 构造测试用默认策略（阈值 3、限速与退避默认、无白名单）
    fn test_policy() -> IpBlockPolicy {
        IpBlockPolicy {
            enabled: true,
            max_failures: 3,
            window_secs: 600,
            max_failed_ips: 100_000,
            max_blocked_ips: 50_000,
            invite_limit: 10,
            invite_window_secs: 60,
            invite_cooldown_secs: 60,
            ban_base_secs: 60,
            ban_factor: 10,
            max_ban_secs: 3600,
            whitelist: Vec::new(),
        }
    }

    /// 把指定 IP 的封锁到期时间拨到过去（模拟封禁时长耗尽）
    fn expire_ban(registrar: &RegistrarService, ip: &str) {
        if let Some(entry) = registrar.blocked_ips.write().unwrap().get_mut(ip) {
            entry.until = now_secs().saturating_sub(1);
        }
    }

    /// 读取指定 IP 当前的剩余封锁时长（秒，用于断言退避等级）
    fn remaining_ban_secs(registrar: &RegistrarService, ip: &str) -> u64 {
        registrar
            .blocked_ips
            .read()
            .unwrap()
            .get(ip)
            .map(|e| e.until.saturating_sub(now_secs()))
            .unwrap_or(0)
    }

    #[test]
    fn unauthed_invite_rate_limit_is_independent_of_blocking() {
        // 未认证 INVITE 限速与封锁完全隔离：大量未认证 INVITE 只触发冷却,不进入封锁表
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                invite_limit: 3,
                ..test_policy()
            },
        );
        let ip = "203.0.113.70";

        // 前 2 次未认证 INVITE 未达阈值,不进入冷却
        for _ in 0..2 {
            assert!(!registrar.is_invite_limited(ip));
            registrar.record_unauthed_invite(ip);
        }
        assert!(!registrar.is_invite_limited(ip), "2 次未达阈值不应冷却");

        // 第 3 次达到阈值,进入冷却
        registrar.record_unauthed_invite(ip);
        assert!(registrar.is_invite_limited(ip), "达到阈值后应进入冷却");

        // 冷却期内不重复计数
        registrar.record_unauthed_invite(ip);

        // 关键断言:未认证 INVITE 不触发封锁、不产生失败计数
        assert!(!registrar.is_blocked(ip), "未认证 INVITE 不应导致 IP 封锁");
        assert!(
            registrar.failed_ips.read().unwrap().is_empty(),
            "未认证 INVITE 不应产生失败计数"
        );
    }

    #[test]
    fn unauthed_invite_cooldown_expires_and_recovers() {
        // 冷却到期后自动恢复,且到期条目被懒清理;恢复后可再次计数并重新触发冷却
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                invite_limit: 2,
                ..test_policy()
            },
        );
        let ip = "203.0.113.71";

        registrar.record_unauthed_invite(ip); // count 1
        registrar.record_unauthed_invite(ip); // count 2 → 冷却
        assert!(registrar.is_invite_limited(ip));

        // 把冷却到期时间拨到过去
        {
            let mut cd = registrar.invite_cooldowns.write().unwrap();
            cd.insert(ip.to_string(), now_secs().saturating_sub(1));
        }
        assert!(!registrar.is_invite_limited(ip), "冷却到期后应解除");
        assert!(
            registrar.invite_cooldowns.read().unwrap().is_empty(),
            "到期条目应被懒清理"
        );

        // 冷却结束后重新计数,再次达到阈值应再次冷却
        registrar.record_unauthed_invite(ip); // count 1
        registrar.record_unauthed_invite(ip); // count 2 → 再次冷却
        assert!(registrar.is_invite_limited(ip), "冷却后应可再次触发");
    }

    #[test]
    fn unauthed_invite_rate_limit_disabled_with_ip_block() {
        // ip_block.enabled = false 时,未认证 INVITE 不限速、不计数
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy::disabled(),
        );
        let ip = "203.0.113.72";
        for _ in 0..100 {
            assert!(!registrar.is_invite_limited(ip));
            registrar.record_unauthed_invite(ip);
        }
        assert!(registrar.invite_counts.read().unwrap().is_empty());
        assert!(registrar.invite_cooldowns.read().unwrap().is_empty());
    }

    #[test]
    fn backoff_escalates_and_caps_duration() {
        // base=60, factor=10, max=3600 → 第 1 次约 60s,第 2 次约 600s,第 3 次封顶 3600s
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                max_failures: 3,
                ..test_policy()
            },
        );
        let ip = "203.0.113.80";

        // 第 1 次封锁：约 60s
        for _ in 0..3 {
            registrar.record_failure(ip);
        }
        assert!(registrar.is_blocked(ip));
        let d1 = remaining_ban_secs(&registrar, ip);
        assert!((60..600).contains(&d1), "第 1 次应约 60s, got {d1}s");

        // 封禁到期（懒清理）→ 自动解封
        expire_ban(&registrar, ip);
        assert!(!registrar.is_blocked(ip), "封禁到期应自动解封");

        // 第 2 次封锁：约 600s
        for _ in 0..3 {
            registrar.record_failure(ip);
        }
        assert!(registrar.is_blocked(ip));
        let d2 = remaining_ban_secs(&registrar, ip);
        assert!((600..3600).contains(&d2), "第 2 次应约 600s, got {d2}s");

        // 到期后再触发第 3 次：封顶 3600s
        expire_ban(&registrar, ip);
        assert!(!registrar.is_blocked(ip));
        for _ in 0..3 {
            registrar.record_failure(ip);
        }
        assert!(registrar.is_blocked(ip));
        let d3 = remaining_ban_secs(&registrar, ip);
        assert!((3590..=3600).contains(&d3), "第 3 次应封顶约 3600s, got {d3}s");

        // 持续触顶也不再超过封顶
        expire_ban(&registrar, ip);
        for _ in 0..3 {
            registrar.record_failure(ip);
        }
        let d4 = remaining_ban_secs(&registrar, ip);
        assert!(d4 <= 3600, "封顶后不再增长, got {d4}s");
    }

    #[test]
    fn auth_success_unblocks_blocked_ip_and_resets_backoff() {
        // 封锁期内携带正确凭据的 REGISTER 应提前解封并正常注册（认证成功提前解封）
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            test_policy(),
        );
        let from: SocketAddr = "203.0.113.81:5061".parse().unwrap();

        // 3 次失败触发封锁
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
        assert!(registrar.is_blocked("203.0.113.81"));

        // 封锁期内正确凭据认证成功 → 200 OK + 提前解封
        let ha1 = md5_hex("1001:example.com:pw");
        let ha2 = md5_hex("REGISTER:sip:example.com");
        let response = md5_hex(&format!("{}:testnonce:{}", ha1, ha2));
        let auth = format!(
            "Authorization: Digest username=\"1001\", realm=\"example.com\", nonce=\"testnonce\", uri=\"sip:example.com\", response=\"{}\"\r\n",
            response
        );
        let resp = registrar.handle_register(&register_request("1001", "ok", &auth), from);
        assert!(
            String::from_utf8(resp).unwrap().starts_with("SIP/2.0 200 OK"),
            "正确凭据应注册成功并解封"
        );
        assert!(!registrar.is_blocked("203.0.113.81"), "认证成功应提前解封");

        // 退避等级已重置：再次触发封锁回到 base（60s）
        for _ in 0..3 {
            registrar.record_failure("203.0.113.81");
        }
        let d = remaining_ban_secs(&registrar, "203.0.113.81");
        assert!((60..600).contains(&d), "认证成功应重置退避等级, 本次应约 60s, got {d}s");
    }

    #[test]
    fn blocked_ip_with_wrong_credentials_stays_blocked() {
        // 封锁期内错误凭据仍 403，不解封（攻击者无正确密码无法利用提前解封）
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            test_policy(),
        );
        let from: SocketAddr = "203.0.113.82:5061".parse().unwrap();

        for _ in 0..3 {
            registrar.handle_register(&register_request("80001", "fail", ""), from);
        }
        assert!(registrar.is_blocked("203.0.113.82"));

        // 携带伪造/错误 response 的 REGISTER：仍 403 且不解封
        let bad_auth = "Authorization: Digest username=\"1001\", realm=\"example.com\", nonce=\"testnonce\", uri=\"sip:example.com\", response=\"deadbeef\"\r\n";
        let resp = registrar.handle_register(&register_request("1001", "bad", bad_auth), from);
        assert_eq!(
            parser::extract_status_code(&String::from_utf8(resp).unwrap()),
            Some(403)
        );
        assert!(registrar.is_blocked("203.0.113.82"), "错误凭据不应解封");

        // 无凭据请求同样 403
        let resp = registrar.handle_register(&register_request("1001", "noauth", ""), from);
        assert_eq!(
            parser::extract_status_code(&String::from_utf8(resp).unwrap()),
            Some(403)
        );
        assert!(registrar.is_blocked("203.0.113.82"));
    }

    #[test]
    fn blocked_ip_wrong_credentials_do_not_extend_block() {
        // 封锁期内错误凭据不刷新/延长封锁（否则攻击者可用任意错误凭据让封锁永不到期）
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            test_policy(),
        );
        let from: SocketAddr = "203.0.113.83:5061".parse().unwrap();

        // 触发封锁
        for _ in 0..3 {
            registrar.handle_register(&register_request("80001", "fail", ""), from);
        }
        assert!(registrar.is_blocked("203.0.113.83"));
        let d_before = remaining_ban_secs(&registrar, "203.0.113.83");
        assert!(d_before > 0);

        // 大量错误凭据请求：封锁时长不应被刷新延长（也不应触发新的退避等级）
        let bad_auth = "Authorization: Digest username=\"1001\", realm=\"example.com\", nonce=\"testnonce\", uri=\"sip:example.com\", response=\"deadbeef\"\r\n";
        for i in 0..20 {
            let resp = registrar.handle_register(
                &register_request("1001", &format!("bad-{}", i), bad_auth),
                from,
            );
            assert_eq!(
                parser::extract_status_code(&String::from_utf8(resp).unwrap()),
                Some(403)
            );
        }
        let d_after = remaining_ban_secs(&registrar, "203.0.113.83");
        assert!(
            d_after <= d_before,
            "错误凭据不应延长封锁: before={d_before}s, after={d_after}s"
        );
        assert!(registrar.is_blocked("203.0.113.83"));
    }

    #[test]
    fn invite_count_tables_respect_capacity_caps() {
        // 海量不同 IP 各发一次未认证 INVITE 不应无限撑爆计数表/冷却表（内存保护）
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                invite_limit: 3,
                invite_window_secs: 60,
                invite_cooldown_secs: 60,
                max_failed_ips: 8,
                max_blocked_ips: 4,
                ..test_policy()
            },
        );

        // 填满计数表：超过上限后应清空保护内存，不死锁/不 panic，且限速仍工作
        for i in 0..20 {
            registrar.record_unauthed_invite(&format!("198.51.1.{}", i % 250));
        }
        let len = registrar.invite_counts.read().unwrap().len();
        assert!(len <= 8, "invite_counts 应受容量上限约束, got {len}");

        // 填满冷却表：达到上限后拒绝新增冷却（降级），不 panic
        for i in 0..20 {
            // 每个 IP 连发 invite_limit 次触发冷却
            let ip = format!("198.51.2.{}", i);
            for _ in 0..3 {
                registrar.record_unauthed_invite(&ip);
            }
        }
        let cooldown_len = registrar.invite_cooldowns.read().unwrap().len();
        assert!(cooldown_len <= 4, "invite_cooldowns 应受容量上限约束, got {cooldown_len}");
    }

    #[test]
    fn whitelisted_ip_is_never_blocked_limited_or_counted() {
        // 白名单命中：不计数、不封锁、不限速（精确 IP 与 CIDR 均生效）
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
            IpBlockPolicy {
                whitelist: vec![
                    // 精确 IP（全位主机 /32）
                    IpNet::new("203.0.113.100".parse().unwrap(), 32).unwrap(),
                    // CIDR 网段
                    "198.51.100.0/24".parse().unwrap(),
                ],
                ..test_policy()
            },
        );

        // 白名单内精确 IP：大量失败不封锁、不计数
        let exact = "203.0.113.100";
        for _ in 0..100 {
            assert!(!registrar.record_failure(exact));
        }
        assert!(!registrar.is_blocked(exact), "白名单 IP 不应被封锁");
        assert!(
            registrar.failed_ips.read().unwrap().is_empty(),
            "白名单 IP 不应产生失败计数"
        );

        // 白名单内 CIDR 命中：不限速、不封锁
        let cidr_hit = "198.51.100.7";
        for _ in 0..100 {
            registrar.record_unauthed_invite(cidr_hit);
        }
        assert!(!registrar.is_invite_limited(cidr_hit), "白名单 IP 不应被限速");
        assert!(!registrar.is_blocked(cidr_hit), "白名单 IP 不应被封锁");

        // 白名单外 IP 正常计数并封锁（证明豁免只作用于白名单）
        let outside = "192.0.2.200";
        for _ in 0..3 {
            registrar.record_failure(outside);
        }
        assert!(registrar.is_blocked(outside), "白名单外 IP 仍应正常封锁");
    }
}
