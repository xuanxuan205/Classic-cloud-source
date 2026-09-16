package com.jdy.cloud.security;

import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.service.ThreatIntelService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;

import java.net.URLDecoder;
import java.security.MessageDigest;
import java.text.Normalizer;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 经典云网盘铁壁安全引擎 IronWall v1.17
 * 主动防御与威慑引擎：特征识别 -> 记分 -> 警告 -> 拖延消耗(Tarpit) -> 自动封禁升级
 * -> IP段封禁 -> 蜜罐诱捕/蜜标触发 -> 证据链落库
 */
@Slf4j
@Service
public class AttackGuardService {

    public static final String ENGINE_NAME = "经典云网盘铁壁安全引擎";
    // IronWall v1.38.1: ban-sync self re-ban hotfix
    // IronWall v1.45.0: 全文件哈希强制 + 分片级哈希绑定 + 账号级指纹
    // IronWall v1.45.1: 平台公告 10 条封顶 + 公告自动弹窗 + 管理后台原生弹窗全替换
    // IronWall v1.45.2: 公告置顶/定时发布 + 已读红点 + 多公告轮播弹窗 + 安全 Markdown 子集
    // IronWall v1.46.0: download_sig 强制+HMAC绑定+24h过期 / UploadPolicy 单一策略源 / 上传阈值下发
    // IronWall v1.47.2: 分享错误响应下发业务码 + 失败精准分类（输错密码不再误报失效）+ 分享页复制链接按钮移除
    // IronWall v1.47.4: 管理后台四项修复（用户归属补全 / 分享下载计入文件计数 / 仪表盘存储与活跃 / 下载统计口径）
    // IronWall v1.47.5: 老账号 user_code 启动自愈补靓号 + 管理端优先显示 5 位靓号
    // IronWall v1.47.6: 靓号固定性（管理员固定 99999）/ 管理端服务端搜索 / 系统信息页精准检测
    // IronWall v1.47.8: 生产域名 CORS 基线（内置白名单可追加不可顶替）
    // IronWall v1.47.9: 第57/58轮报告整改——分享 zip 递归打包+双上限+zip-slip 防线 / 下载 Accept-Ranges 收敛 / SVG 解析级白名单 / 封禁页稳定原因码 / 限流文案秒级对齐
    // IronWall v1.47.10: 通知设置闭环——读写键名契约修正 / 保存失败不再假装成功 / GET 只读消除并发竞态 / 四个开关接入真实消费方 / 浏览器通知权限与公告推送落地
    // IronWall v1.47.11: 分享下载审计归属修复——访客下载不再记成分享者本人操作 / 独立动作码 share_download / 详情回填分享者与分享码前缀
    public static final String ENGINE_VERSION = "v1.48.0";
    public static final String ENGINE_FULL_NAME = ENGINE_NAME + " IronWall " + ENGINE_VERSION;


    // IronWall v1.23.0: 服务器层联动桥——攻击封禁事件写入专用日志，fail2ban 读取后全端口封禁
    private static final org.slf4j.Logger F2B_LOG = org.slf4j.LoggerFactory.getLogger("IRONWALL-F2B");

    public static final String TYPE_SQL = "SQL注入";
    public static final String TYPE_XSS = "XSS攻击";
    public static final String TYPE_TRAVERSAL = "路径穿越";
    public static final String TYPE_CMD = "命令注入";
    public static final String TYPE_SSRF = "SSRF探测";
    public static final String TYPE_TOOL = "扫描工具";
    public static final String TYPE_CRAWLER = "爬虫扫描";
    public static final String TYPE_SUSPICIOUS_PATH = "路径异常探测";
    public static final String TYPE_HONEYPOT = "蜜罐诱捕";
    public static final String TYPE_SEGMENT = "IP段封禁";
    public static final String TYPE_PROTOCOL = "协议异常";
    public static final String TYPE_TRAP = "陷阱吞没";
    // IronWall v1.28.15: 跨IP协同攻击（同载荷指纹多来源联动封禁）
    public static final String TYPE_CAMPAIGN = "跨IP协同攻击";
    // IronWall v1.28.16: 设备指纹锁定（换 IP 也无效，仅在真实攻击触发封禁时锁定）
    public static final String TYPE_FINGERPRINT = "设备指纹锁定";
    // IronWall v1.31.0: TLS 会话指纹跨 IP 证据（JA4 近似，仅对已计分攻击 IP 加速）
    public static final String TYPE_TLS = "TLS指纹联动";
    // IronWall v1.32.0: 攻击模板指纹跨 IP 聚合（载荷字面量归一化后联动封禁）
    public static final String TYPE_TEMPLATE = "攻击模板聚合";
    // IronWall v1.38.0: 封禁同步事件（attack_logs 事件总线，多实例封禁名单对账）
    public static final String TYPE_SYNC = "封禁同步事件";

    // IronWall v1.37.0: 计分分级——协议异常/探测 2 分、明确攻击 5 分、高危(陷阱) 20 分。
    // 协议异常只累积、不单次直封（闭环）；爬虫/SSRF 保留历史低分决策防误伤。
    public static final int SCORE_NOISE = 2;
    public static final int SCORE_CRAWLER = 1;
    public static final int SCORE_SSRF = 3;
    public static final int SCORE_ATTACK = 5;
    public static final int SCORE_SEVERE = 20;

    // IronWall v1.38.1: 实例标识改为“主机名|端口|应用”稳定指纹——重启不换UUID，避免把自身历史同步事件当远端实例而复封
    @Value("${server.port:15060}")
    private int serverPort;

    @Value("${spring.application.name:jdy-cloud}")
    private String appName;

    private volatile String instanceId;

    // IronWall v1.38.0: 告警联动（可选注入；测试/未装配时静默跳过）
    private volatile AlertNotifierService alertNotifier;

    @Autowired(required = false)
    public void setAlertNotifier(AlertNotifierService alertNotifier) {
        this.alertNotifier = alertNotifier;
    }

    private static final Pattern SQLI = IronWallRules.p("patterns.sqli");
    // IronWall v1.28.9: || / && 拼接运算符与无空格 or/and 引号变体（admin'||' / '||'1'='1）
    private static final Pattern SQLI_OPERATOR = IronWallRules.p("patterns.sqliOperator");
    // IronWall v1.28.13: 历史发现的 LIKE/REGEXP 运算族盲区（变体）。
    // 防误报约束：运算词必须被引号/数字/括号锚定或为 SQL 专有函数形态，
    // 自然语言（"I like this" / "I'm in the zone" / "having trouble"）不命中。
    private static final Pattern SQLI_OPERATOR_FAMILY = IronWallRules.p("patterns.sqliOperatorFamily");
    // IronWall v1.34.0: MySQL 内置语法族盲区（@@系统变量 / 信息函数 / '.'点拼接）。
    // 防误报约束：@@ 只认变量名形态；函数名必须紧跟 (；点拼接必须两侧引号锚定。
    private static final Pattern SQLI_MYSQL_BUILTIN = IronWallRules.p("patterns.sqliMysqlBuiltin");
    // IronWall v1.26.1: 0x hex is only a strong signal in request payloads, not in
    // User-Agent / Referer. WeChat MicroMessenger uses "(0x18004b62)" and was being banned.
    private static final Pattern SQLI_HEX = IronWallRules.p("patterns.sqliHex");
    private static final Pattern XSS = IronWallRules.p("patterns.xss");
    private static final Pattern TRAVERSAL = IronWallRules.p("patterns.traversal");
    private static final Pattern CMD = IronWallRules.p("patterns.cmd");
    private static final Pattern SSRF = IronWallRules.p("patterns.ssrf");
    // IronWall v1.7: 路径异常单独归类低分，避免误报面刷分消耗封禁名额
    private static final Pattern SUSPICIOUS_PATH = IronWallRules.p("patterns.suspiciousPath");
    // IronWall v1.11: 常见爬虫/自动化客户端指纹（仅记分，不直接封禁，重复触发才升级封禁）
    private static final Pattern CRAWLER_UA = IronWallRules.p("patterns.crawlerUa");
    private static final Pattern TOOL_UA = IronWallRules.p("patterns.toolUa");

    // IronWall v1.26.2: 登录/上传/管理端等高危路径——真实攻击类型按高权重记分
    // （权重 10→6，4 击即封，闭环），
    // 普通浏览路径保持原权重，避免正常用户误伤（建议 差异化阈值）
    // IronWall v1.48.0：本应用自身路由的分类器，不属于攻击特征，缺失时用内置默认值，
    // 否则「高危路径加权」会静默失效，而不是安全降级。
    private static final Pattern HIGH_RISK_PATH = IronWallRules.p("patterns.highRiskPath",
            "(?i)(/api/auth/(login|register|verify-code|reset-password|change-password)(/|$)"
          + "|/api/admin(/|$)|/api/files/upload|/api/shares/download(-zip)?)");

    // IronWall v1.39.0: multipart 误封补偿——NULL字节截断误报专用上传端点签名
    private static final Pattern UPLOAD_PATH = IronWallRules.p("patterns.uploadPath",
            "(?i)(/api/auth/upload-avatar|/api/files/upload(/chunk)?)$");

    // IronWall v1.5 E-01: JSON Unicode 转义与 SQL 注释分割归一化
    private static final Pattern JSON_UNICODE_ESCAPE = IronWallRules.p("patterns.jsonUnicodeEscape");
    // IronWall v1.28.15: JSON 字符串转义（\t \n \r \f \b \" \' \\ \/）解码为空白/字面字符
    private static final Pattern JSON_STRING_ESCAPE = IronWallRules.p("patterns.jsonStringEscape");
    private static final Pattern SQL_INLINE_COMMENT = IronWallRules.p("patterns.sqlInlineComment");
    // IronWall v1.30.0: 双写关键词（OORR/ANANDD/UNIUNIONON...），词界锚定递归清洗还原
    // IronWall v1.33.0: 蜜标账号提取（登录接口 username 参数，query/form 共用）
    // IronWall v1.48.0：以下两条只是「从请求里取出 username」的解析器，判断的不是攻击，
    // 缺失会让登录蜜标整体失效，故内置默认值。
    private static final Pattern USERNAME_PARAM = IronWallRules.p("patterns.usernameParam",
            "(?:^|[?&])username=([^&\\s]{1,64})");
    private static final Pattern USERNAME_JSON = IronWallRules.p("patterns.usernameJson",
            "\"username\"\\s*:\\s*\"([^\"\\\\]{1,64})\"");
    private static final Pattern DOUBLE_WRITE_TOKEN = IronWallRules.p("patterns.doubleWriteToken");
    // IronWall v1.28.9: Unicode 空白/零宽字符归一化，防止关键字被空格变体拆分绕过
    private static final Pattern UNICODE_WS = IronWallRules.p("patterns.unicodeWhitespace");

    private static final int MAX_PAYLOAD_LOG_LENGTH = 500;
    // IronWall v1.24.0: 人机验证挑战有效期 5 分钟，失败计数滑动窗口 10 分钟
    private static final long CHALLENGE_TTL_MS = 5 * 60_000L;
    private static final long CHALLENGE_ATTEMPT_WINDOW_MS = 10 * 60_000L;
    private static final Random RANDOM = new Random();
    @Value("${app.security.attack-guard.enabled:true}")
    private boolean enabled;

    // IronWall v1.28.13: 运算族规则独立开关（误报时可单独回滚）。
    @Value("${app.security.attack-guard.operator-family.enabled:true}")
    private boolean operatorFamilyEnabled;

    // IronWall v1.34.0: MySQL 内置语法族规则独立开关（误报时可单独回滚）。
    @Value("${app.security.attack-guard.mysql-builtin.enabled:true}")
    private boolean mysqlBuiltinEnabled;

    // IronWall v1.31.0: SQL 词法/语义检测层（正则层未命中后运行，可独立回滚）
    @Value("${app.security.attack-guard.semantic.enabled:true}")
    private boolean semanticEnabled;

    private final SqlSemanticAnalyzer semanticAnalyzer = new SqlSemanticAnalyzer();

    // IronWall v1.28.15: 跨IP协同攻击检测（同载荷指纹多来源联动封禁，打击代理池轮换）。
    @Value("${app.security.attack-guard.campaign.enabled:true}")
    private boolean campaignEnabled;

    @Value("${app.security.attack-guard.campaign.min-ips:3}")
    private int campaignMinIps;

    @Value("${app.security.attack-guard.campaign.window-minutes:10}")
    private int campaignWindowMinutes;

    @Value("${app.security.attack-guard.campaign.block-minutes:120}")
    private int campaignBlockMinutes;

    private final ConcurrentHashMap<String, CampaignHit> campaignHits = new ConcurrentHashMap<>();

    // IronWall v1.30.0: 攻击族×路径跨IP聚合（代理池+每请求新载荷式扫描，≥N 个攻击 IP 全部封禁）。
    @Value("${app.security.attack-guard.family.enabled:true}")
    private boolean familyEnabled;

    @Value("${app.security.attack-guard.family.min-ips:8}")
    private int familyMinIps;

    @Value("${app.security.attack-guard.family.window-minutes:30}")
    private int familyWindowMinutes;

    @Value("${app.security.attack-guard.family.block-minutes:120}")
    private int familyBlockMinutes;

    private final ConcurrentHashMap<String, FingerprintHit> attackFamilyHits = new ConcurrentHashMap<>();

    // IronWall v1.31.0: TLS 会话指纹（JA4 近似）跨 IP 攻击证据——仅对已计分攻击 IP 加速计分。
    @Value("${app.security.attack-guard.tls-profile.enabled:true}")
    private boolean tlsProfileEnabled;

    @Value("${app.security.attack-guard.tls-profile.min-ips:2}")
    private int tlsProfileMinIps;

    @Value("${app.security.attack-guard.tls-profile.window-minutes:1440}")
    private int tlsProfileWindowMinutes;

    @Value("${app.security.attack-guard.tls-profile.boost-weight:10}")
    private int tlsProfileBoostWeight;

    private final ConcurrentHashMap<String, FingerprintHit> tlsSightings = new ConcurrentHashMap<>();

    // IronWall v1.32.0: 攻击模板指纹聚合（载荷字面量归一化后跨IP联动封禁，成员必须真实攻击）
    @Value("${app.security.attack-guard.template.enabled:true}")
    private boolean templateEnabled;

    @Value("${app.security.attack-guard.template.min-ips:3}")
    private int templateMinIps;

    @Value("${app.security.attack-guard.template.window-minutes:10}")
    private int templateWindowMinutes;

    @Value("${app.security.attack-guard.template.block-minutes:120}")
    private int templateBlockMinutes;

    private final ConcurrentHashMap<String, FingerprintHit> templateHits = new ConcurrentHashMap<>();

    // IronWall v1.32.0: TLS 指纹先手封禁（集群已触发后，同指纹新攻击成员首发即封）
    @Value("${app.security.attack-guard.tls-profile.escalate-enabled:true}")
    private boolean tlsProfileEscalateEnabled;

    @Value("${app.security.attack-guard.tls-profile.escalate-block-minutes:120}")
    private int tlsProfileEscalateBlockMinutes;

    // IronWall v1.32.0: 代理/机房信誉放大器（仅放大真实攻击计分，绝不单独封禁）
    @Value("${app.security.attack-guard.proxy-reputation.enabled:true}")
    private boolean proxyReputationEnabled;

    @Value("${app.security.attack-guard.proxy-reputation.boost:10}")
    private int proxyReputationBoost;

    // IronWall v1.33.0: 登录接口蜜标账号诱捕（随机假账号，提交即高置信攻击，零误伤）
    @Value("${app.security.attack-guard.login-honeypot.enabled:true}")
    private boolean loginHoneypotEnabled;

    // 蜜标账号名由部署者在 .env / 配置中填写，取值应选正常用户绝不会提交的名字；
    // 留空即该防线停用。
    @Value("${app.security.attack-guard.login-honeypot.usernames:}")
    private String loginHoneypotUsernames;

    // IronWall v1.33.0: 模板相似度第二层（3-gram Jaccard 合并结构微调载荷）
    @Value("${app.security.attack-guard.template.similarity-enabled:true}")
    private boolean templateSimilarityEnabled;

    @Value("${app.security.attack-guard.template.similarity-threshold:0.75}")
    private double templateSimilarityThreshold;

    private static final int TEMPLATE_GRAM_N = 3;
    private static final int SIMILAR_BUCKET_MAX = 512;
    private final ConcurrentHashMap<String, SimilarTemplateHit> similarTemplateHits = new ConcurrentHashMap<>();

    // IronWall v1.28.16: 设备指纹锁定。封禁瞬间锁定指纹，换代理 IP 同样被拦截；
    // 仅在真实攻击类型命中且触发 IP 封禁后锁定，正常用户与共用出口 IP 的其他设备不受影响。
    @Value("${app.security.attack-guard.fingerprint.enabled:true}")
    private boolean fingerprintEnabled;

    @Value("${app.security.attack-guard.fingerprint.min-ips:2}")
    private int fingerprintMinIps;

    @Value("${app.security.attack-guard.fingerprint.block-minutes:120}")
    private int fingerprintBlockMinutes;

    @Value("${app.security.attack-guard.fingerprint.window-minutes:1440}")
    private int fingerprintWindowMinutes;

    // IronWall v1.29.0: 指纹轮换规避检测（同设备短时间内更换多个指纹视为规避，锁定设备ID）
    @Value("${app.security.attack-guard.fingerprint.churn-min-fps:3}")
    private int fingerprintChurnMinFps;

    @Value("${app.security.attack-guard.fingerprint.churn-window-minutes:60}")
    private int fingerprintChurnWindowMinutes;

    // IronWall v1.29.0: 设备级跨 IP 证据（同设备ID从多个IP发起真实攻击，锁定设备）
    @Value("${app.security.attack-guard.device.min-ips:2}")
    private int deviceMinIps;

    @Value("${app.security.attack-guard.device.window-minutes:1440}")
    private int deviceWindowMinutes;

    /** identity -> 锁定状态（fp 与 did 共用） */
    private final ConcurrentHashMap<String, IdentityJail> identityJails = new ConcurrentHashMap<>();
    /** 同一指纹在不同 IP 上发起攻击的证据累积（仅记录，不直接封禁） */
    private final ConcurrentHashMap<String, FingerprintHit> fingerprintHits = new ConcurrentHashMap<>();
    /** 同一设备ID在不同 IP 上发起攻击的证据累积（防指纹随机化规避） */
    private final ConcurrentHashMap<String, FingerprintHit> deviceHits = new ConcurrentHashMap<>();
    /** 设备ID下观察到的指纹集合（轮换过快判定规避行为） */
    private final ConcurrentHashMap<String, DeviceChurn> deviceFpChurn = new ConcurrentHashMap<>();

    @Value("${app.security.attack-guard.warn-score:10}")
    private int warnScore;

    @Value("${app.security.attack-guard.block-score:20}")
    private int blockScore;

    @Value("${app.security.attack-guard.severe-block-score:40}")
    private int severeBlockScore;

    @Value("${app.security.attack-guard.block-minutes:30}")
    private int blockMinutes;

    @Value("${app.security.attack-guard.severe-block-hours:24}")
    private int severeBlockHours;

    @Value("${app.security.fail2ban-bridge.enabled:true}")
    private boolean fail2banBridgeEnabled;

    // IronWall v1.24.0: 单发即封的人机验证二次确认挑战
    @Value("${app.security.attack-guard.challenge.enabled:true}")
    private boolean challengeEnabled;

    @Value("${app.security.attack-guard.challenge.max-attempts:5}")
    private int challengeMaxAttempts;

    // IronWall v1.26.2: 人机验证 token HMAC 签名密钥（未配置时每进程随机生成，重启即失效）
    @Value("${app.security.attack-guard.challenge.secret:}")
    private String challengeSecret;

    // IronWall v1.39.0: 高危路径攻击权重（默认 6 分/击，4 击越过封禁线）。
    // 报告 闭环：2 击即封过严，正常用户误触 2 次不应被封；WARN 先于封禁。
    @Value("${app.security.attack-guard.challenge.high-risk-path-weight:6}")
    private int highRiskPathWeight;

    private volatile String challengeKey;

    // IronWall v1.25.0: WARN 计分时间衰减窗口（毫秒），正常用户误触不累积升级
    @Value("${app.security.attack-guard.score-decay-window-ms:1800000}")
    private long scoreDecayWindowMs;

    // IronWall v1.26.0: 爬虫/合法自动化客户端专属快速衰减窗口，避免低频 API 集成方累积封禁
    @Value("${app.security.attack-guard.crawler-decay-window-ms:300000}")
    private long crawlerDecayWindowMs;

    @Value("${app.security.defense-engine.segment-block.enabled:true}")
    private boolean segmentBlockEnabled;

    @Value("${app.security.defense-engine.segment-block.repeat-offense-count:3}")
    private int segmentRepeatCount;

    @Value("${app.security.defense-engine.segment-block.block-hours:48}")
    private int segmentBlockHours;

    // IronWall v1.42.0: 移动/家宽运营商出口误封熔断（真实用户零误伤）
    @Value("${app.security.attack-guard.mobile-carrier.enabled:true}")
    private boolean mobileCarrierProtectEnabled;

    @Value("${app.security.attack-guard.mobile-carrier.max-block-minutes:30}")
    private int mobileCarrierMaxBlockMinutes;

    // IronWall v1.44.0: 移动/家宽运营商出口熔断面板统计（累计值，重启清零）
    private final AtomicLong mobileFuseBlockCapHits = new AtomicLong();
    private final AtomicLong mobileFuseSegmentSkips = new AtomicLong();


    private final AttackLogRepository attackLogRepository;
    private final Map<String, IpState> ipStates = new ConcurrentHashMap<>();
    private final Map<String, SegmentState> segmentStates = new ConcurrentHashMap<>();
    private final Map<String, ChallengeEntry> challenges = new ConcurrentHashMap<>();


    public AttackGuardService(AttackLogRepository attackLogRepository) {
        this.attackLogRepository = attackLogRepository;
    }

    /**
     * IronWall v1.42.0: 威胁情报回填（ThreatIntelService 初始化完成后调用，
     * 规避构造器循环依赖）。仅作缓存查询，绝不发起网络请求。
     */
    private volatile ThreatIntelService threatIntelService;

    public void attachThreatIntel(ThreatIntelService service) {
        this.threatIntelService = service;
    }

    private boolean isMobileCarrierIp(String ip) {
        if (!mobileCarrierProtectEnabled || ip == null) {
            return false;
        }
        ThreatIntelService intel = threatIntelService;
        try {
            return intel != null && intel.isMobileCarrierCached(ip);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * IronWall v1.44.0: 移动/家宽运营商出口熔断面板统计。
     * block_cap_hits = 封禁时长被压顶的次数（防 NAT/CGNAT 连坐）；
     * segment_skips = 整段封禁豁免次数。
     */
    public Map<String, Object> mobileFuseStats() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", mobileCarrierProtectEnabled);
        out.put("max_block_minutes", Math.max(10, mobileCarrierMaxBlockMinutes));
        out.put("block_cap_hits", mobileFuseBlockCapHits.get());
        out.put("segment_skips", mobileFuseSegmentSkips.get());
        return out;
    }

    /**
     * IronWall v1.28.13: 只读信誉分（PoW 动态难度等场景使用），无状态返回 0。
     */
    public int scoreOf(String ip) {
        if (ip == null) return 0;
        IpState state = ipStates.get(ip);
        return state == null ? 0 : Math.max(0, state.score);
    }

    /**
     * IronWall v1.28.15: 跨IP协同攻击检测。同一归一化载荷（type+SHA256 指纹）
     * 在窗口期内来自 >= minIps 个不同来源 IP，即判定为代理池协同攻击，
     * 联动封禁全部来源（保守阈值：仅单 IP / 双 IP 不触发，规避 NAT 与双栈误伤）。
     */
    private void registerCampaignHit(String type, String payload, String ip) {
        if (!campaignEnabled || campaignMinIps <= 1) return;
        if (!isRealAttackType(type) || ip == null || payload == null || payload.length() < 8) return;
        try {
            String fingerprint = type + "|" + sha256Hex(payload).substring(0, 16);
            long windowMs = campaignWindowMinutes > 0 ? campaignWindowMinutes * 60_000L : 600_000L;
            long now = System.currentTimeMillis();
            CampaignHit hit = campaignHits.computeIfAbsent(fingerprint, k -> new CampaignHit());
            if (now - hit.firstSeen > windowMs) {
                campaignHits.remove(fingerprint, hit);
                CampaignHit fresh = new CampaignHit();
                CampaignHit existing = campaignHits.putIfAbsent(fingerprint, fresh);
                hit = existing != null ? existing : fresh;
            }
            hit.ips.add(ip);
            if (!hit.tripped && hit.ips.size() >= campaignMinIps) {
                hit.tripped = true;
                for (String member : hit.ips) {
                    campaignBlock(member, payload);
                }
            }
        } catch (Exception e) {
            log.error("[IronWall] campaign tracking failed: {}", e.getMessage());
        }
    }

    private void campaignBlock(String ip, String payload) {
        IpState state = ipStates.computeIfAbsent(ip, k -> new IpState());
        long minutes = campaignBlockMinutes > 0 ? campaignBlockMinutes : 120;
        synchronized (state) {
            long now = System.currentTimeMillis();
            state.blockedUntil = Math.max(state.blockedUntil, now + minutes * 60_000L);
            state.blockCount++;
            state.lastSeen = now;
        }
        persistLog(ip, TYPE_CAMPAIGN, payload, "/", "system", "SYSTEM", 20, "BLOCKED");
        log.warn("[IronWall] CAMPAIGN TRIGGERED: ip={} payload={}",
                ip, payload.length() > 80 ? payload.substring(0, 80) : payload);
    }

    /**
     * IronWall v1.30.0: 攻击族×路径跨 IP 聚合。
     * 同一（攻击类型×路径）在窗口期内来自 >= minIps 个不同 IP 的真实攻击，
     * 即判定为「代理池 + 每请求新载荷」式集群扫描，联动封禁全部参与 IP。
     * 仅计分过的攻击 IP 参与聚合，正常流量零参与、零误伤。
     */
    private void registerAttackFamilyHit(String type, String path, String ip) {
        if (!familyEnabled || familyMinIps <= 1 || ip == null) return;
        if (!isRealAttackType(type)) return;
        try {
            String key = (type == null ? "?" : type) + "|" + (path == null || path.isBlank() ? "/" : path);
            long windowMs = familyWindowMinutes > 0 ? familyWindowMinutes * 60_000L : 1_800_000L;
            long now = System.currentTimeMillis();
            FingerprintHit hit = attackFamilyHits.computeIfAbsent(key, k -> new FingerprintHit());
            if (now - hit.firstSeen > windowMs) {
                attackFamilyHits.remove(key, hit);
                FingerprintHit fresh = new FingerprintHit();
                FingerprintHit existing = attackFamilyHits.putIfAbsent(key, fresh);
                hit = existing != null ? existing : fresh;
            }
            hit.ips.add(ip);
            if (!hit.tripped && hit.ips.size() >= familyMinIps) {
                hit.tripped = true;
                long minutes = familyBlockMinutes > 0 ? familyBlockMinutes : 120;
                int effectiveBlockScore = blockScore > 0 ? blockScore : 20;
                for (String member : hit.ips) {
                    IpState st = ipStates.computeIfAbsent(member, k -> new IpState());
                    synchronized (st) {
                        st.score = Math.max(st.score, effectiveBlockScore);
                        st.blockedUntil = Math.max(st.blockedUntil, now + minutes * 60_000L);
                        st.blockCount++;
                        st.lastSeen = now;
                    }
                    persistLog(member, TYPE_CAMPAIGN, "攻击族聚合封禁: " + key, path, "system", "SYSTEM",
                            st.score, "BLOCKED");
                }
                log.warn("[IronWall] ATTACK FAMILY TRIGGERED: key={} memberCount={}", key, hit.ips.size());
            }
        } catch (Exception e) {
            log.error("[IronWall] attack family tracking failed: {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.32.0: 攻击模板指纹跨 IP 聚合。
     * 载荷字面量归一化（数字/十六进制/引号串一律塌缩）后，同一（类型×路径×模板）
     * 在窗口期内来自 >= minIps 个不同 IP 的真实攻击，即判定为「代理池 + 每请求微调载荷」
     * 式集群扫描，联动封禁全部参与 IP。仅计分过的真实攻击参与，正常流量零参与、零误伤。
     */
    private void registerTemplateHit(String type, String path, String payload, String ip) {
        if (!templateEnabled || templateMinIps <= 1 || ip == null) return;
        if (!isRealAttackType(type) || payload == null || payload.length() < 8) return;
        try {
            String template = attackTemplateOf(payload);
            if (template == null || template.length() < 8) return;
            String key = (type == null ? "?" : type)
                    + "|" + (path == null || path.isBlank() ? "/" : path)
                    + "|" + sha256Hex(template).substring(0, 16);
            long windowMs = templateWindowMinutes > 0 ? templateWindowMinutes * 60_000L : 600_000L;
            long now = System.currentTimeMillis();
            // IronWall v1.33.0: 结构微调载荷经相似桶合并到同一聚合键
            if (templateSimilarityEnabled && similarTemplateHits.size() < SIMILAR_BUCKET_MAX) {
                key = similarBucketKeyOf(key, template, windowMs, now);
            }
            FingerprintHit hit = templateHits.computeIfAbsent(key, k -> new FingerprintHit());
            if (now - hit.firstSeen > windowMs) {
                templateHits.remove(key, hit);
                FingerprintHit fresh = new FingerprintHit();
                FingerprintHit existing = templateHits.putIfAbsent(key, fresh);
                hit = existing != null ? existing : fresh;
            }
            hit.ips.add(ip);
            if (!hit.tripped && hit.ips.size() >= templateMinIps) {
                hit.tripped = true;
                long minutes = templateBlockMinutes > 0 ? templateBlockMinutes : 120;
                int effectiveBlockScore = blockScore > 0 ? blockScore : 20;
                for (String member : hit.ips) {
                    IpState st = ipStates.computeIfAbsent(member, k -> new IpState());
                    synchronized (st) {
                        st.score = Math.max(st.score, effectiveBlockScore);
                        st.blockedUntil = Math.max(st.blockedUntil, now + minutes * 60_000L);
                        st.blockCount++;
                        st.lastSeen = now;
                    }
                    persistLog(member, TYPE_TEMPLATE, templateLabel(key, template), path, "system", "SYSTEM",
                            st.score, "BLOCKED");
                }
                log.warn("[IronWall] ATTACK TEMPLATE TRIGGERED: template={} memberCount={}", template, hit.ips.size());
            }
        } catch (Exception e) {
            log.error("[IronWall] attack template tracking failed: {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.33.0: 相似桶合并。模板 3-gram 与活跃桶的 Jaccard 最高分 >= 阈值
     * 时合并到该桶（复用其聚合键），否则新建桶。桶数上限防内存膨胀。
     */
    private String similarBucketKeyOf(String exactKey, String template, long windowMs, long now) {
        Set<String> grams = templateGrams(template);
        if (grams.isEmpty()) return exactKey;
        String bestKey = null;
        double bestScore = -1;
        for (Map.Entry<String, SimilarTemplateHit> e : similarTemplateHits.entrySet()) {
            SimilarTemplateHit bucket = e.getValue();
            if (now - bucket.firstSeen > windowMs) continue;
            double score = jaccard(grams, bucket.grams);
            if (score > bestScore) {
                bestScore = score;
                bestKey = e.getKey();
            }
        }
        double threshold = templateSimilarityThreshold > 0 && templateSimilarityThreshold <= 1
                ? templateSimilarityThreshold : 0.75;
        if (bestKey != null && bestScore >= threshold) {
            return bestKey;
        }
        similarTemplateHits.put(exactKey, new SimilarTemplateHit(grams, template));
        return exactKey;
    }

    private Set<String> templateGrams(String template) {
        Set<String> grams = new HashSet<>();
        if (template.length() < TEMPLATE_GRAM_N) {
            grams.add(template);
            return grams;
        }
        for (int i = 0; i + TEMPLATE_GRAM_N <= template.length(); i++) {
            grams.add(template.substring(i, i + TEMPLATE_GRAM_N));
        }
        return grams;
    }

    private double jaccard(Set<String> a, Set<String> b) {
        if (a.isEmpty() || b.isEmpty()) return 0;
        int inter = 0;
        for (String g : a) {
            if (b.contains(g)) inter++;
        }
        int union = a.size() + b.size() - inter;
        return union <= 0 ? 0 : (double) inter / union;
    }

    private String templateLabel(String key, String template) {
        SimilarTemplateHit bucket = similarTemplateHits.get(key);
        if (bucket != null && !bucket.template.equals(template)) {
            return "相似模板聚合封禁: " + bucket.template + " ~ " + template;
        }
        return "攻击模板聚合封禁: " + template;
    }

    /**
     * IronWall v1.32.0: 载荷模板归一化。
     * NFKC 归一 → 小写 → 0x 十六进制字面量塌缩为 H → 十进制数字塌缩为 N →
     * 引号串塌缩为 'S'/"S" → 空白折叠 → trim。字面量微调的攻击变体收敛为同一模板。
     */
    private String attackTemplateOf(String payload) {
        if (payload == null) return null;
        String t = Normalizer.normalize(payload, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        t = t.replaceAll("0x[0-9a-f]{2,}", "H");
        t = t.replaceAll("[0-9]+", "N");
        t = t.replaceAll("'[^']*'", "'S'").replaceAll("\"[^\"]*\"", "\"S\"");
        t = t.replaceAll("\\s+", " ");
        return t.trim();
    }

    /**
     * IronWall v1.31.0: TLS 会话指纹（JA4 近似）跨 IP 攻击证据。
     * 同一指纹在窗口内来自 >= minIps 个不同 IP 的真实攻击（调用方仅在命中攻击时登记），
     * 对参与 IP 加固定分值加速封禁。指纹为共享特征，绝不按指纹封锁流量。
     */
    public void registerTlsSighting(String profileKey, String ip) {
        if (!tlsProfileEnabled || tlsProfileMinIps <= 1) return;
        if (profileKey == null || profileKey.length() < 8 || profileKey.length() > 128 || ip == null) return;
        try {
            long windowMs = tlsProfileWindowMinutes > 0 ? tlsProfileWindowMinutes * 60_000L : 86_400_000L;
            long now = System.currentTimeMillis();
            FingerprintHit hit = tlsSightings.computeIfAbsent(profileKey, k -> new FingerprintHit());
            if (now - hit.firstSeen > windowMs) {
                tlsSightings.remove(profileKey, hit);
                FingerprintHit fresh = new FingerprintHit();
                FingerprintHit existing = tlsSightings.putIfAbsent(profileKey, fresh);
                hit = existing != null ? existing : fresh;
            }
            boolean isNew = hit.ips.add(ip);
            if (!hit.tripped && hit.ips.size() >= tlsProfileMinIps) {
                hit.tripped = true;
                for (String member : hit.ips) {
                    boostTlsMember(member, profileKey);
                }
            } else if (hit.tripped && isNew) {
                // IronWall v1.32.0: 集群已触发后，同指纹新攻击成员首发即封；
                // escalate-enabled=false 时回滚为旧 +boost 加速模式。
                if (tlsProfileEscalateEnabled) {
                    blockTlsEscalateMember(ip, profileKey, now);
                } else {
                    boostTlsMember(ip, profileKey);
                }
            }
        } catch (Exception e) {
            log.error("[IronWall] TLS profile sighting failed: {}", e.getMessage());
        }
    }

    /** IronWall v1.32.0: TLS 指纹先手封禁——集群已触发后的同指纹新攻击成员，首发即封。 */
    private void blockTlsEscalateMember(String ip, String profileKey, long now) {
        int effectiveBlockScore = blockScore > 0 ? blockScore : 20;
        long minutes = tlsProfileEscalateBlockMinutes > 0 ? tlsProfileEscalateBlockMinutes : 120;
        IpState st = ipStates.computeIfAbsent(ip, k -> new IpState());
        synchronized (st) {
            st.score = Math.max(st.score, effectiveBlockScore);
            st.blockedUntil = Math.max(st.blockedUntil, now + minutes * 60_000L);
            st.blockCount++;
            st.lastSeen = now;
        }
        persistLog(ip, TYPE_TLS, "TLS指纹先手封禁: " + profileKey, "/", "system", "SYSTEM", st.score, "BLOCKED");
        log.warn("[IronWall] TLS PROFILE ESCALATE: ip={} profile={} blocked", ip, profileKey);
    }

    private void boostTlsMember(String ip, String profileKey) {
        int boost = tlsProfileBoostWeight > 0 ? tlsProfileBoostWeight : 10;
        IpState st = ipStates.computeIfAbsent(ip, k -> new IpState());
        synchronized (st) {
            st.score = Math.max(0, st.score) + boost;
            st.lastSeen = System.currentTimeMillis();
        }
        persistLog(ip, TYPE_TLS, "TLS会话指纹跨IP证据: " + profileKey, "/", "system", "SYSTEM", st.score, "WARN");
        log.warn("[IronWall] TLS PROFILE SIGHTING: ip={} profile={}", ip, profileKey);
    }

    /** IronWall v1.32.0: 供过滤器读取代理/机房信誉放大分值（开关关闭时恒为 0）。 */
    public int proxyReputationBoost() {
        return proxyReputationEnabled ? proxyReputationBoost : 0;
    }

    /**
     * IronWall v1.33.0: 登录蜜标账号匹配。仅 POST/PUT 登录接口；
     * 提取 username 参数与随机假账号精确比对，命中返回账号名（调用方按高置信攻击处置），否则 null。
     * 真实用户不可能提交这些随机账号，零误伤。
     */
    public String matchLoginHoneypot(String uri, String method, String queryString, String body) {
        if (!loginHoneypotEnabled || uri == null) return null;
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        if (!("POST".equals(m) || "PUT".equals(m))) return null;
        String path = uri;
        int q = path.indexOf('?');
        if (q >= 0) path = path.substring(0, q);
        if (path.endsWith("/")) path = path.substring(0, path.length() - 1);
        // IronWall v1.48.0：守护的接口路径可由外部规则文件覆盖；未配置时回退到本站登录端点。
        // 这是本应用自己的路由，不配置也必须能工作，否则蜜标防线会静默失效。
        String guardedPath = IronWallRules.str("honeypot.loginPath", "/api/auth/login");
        if (!guardedPath.equals(path)) return null;
        Set<String> baits = loginHoneypotBaitSet();
        if (baits.isEmpty()) return null;
        String username = extractUsername(queryString, body);
        if (username == null) return null;
        return baits.contains(username.toLowerCase(Locale.ROOT)) ? username : null;
    }

    private Set<String> loginHoneypotBaitSet() {
        Set<String> set = new HashSet<>();
        if (loginHoneypotUsernames == null) return set;
        for (String part : loginHoneypotUsernames.split(",")) {
            String t = part.trim().toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) set.add(t);
        }
        return set;
    }

    private String extractUsername(String queryString, String body) {
        if (queryString != null) {
            Matcher m = USERNAME_PARAM.matcher(queryString);
            if (m.find()) return m.group(1);
        }
        if (body != null) {
            Matcher m = USERNAME_JSON.matcher(body);
            if (m.find()) return m.group(1);
            m = USERNAME_PARAM.matcher(body);
            if (m.find()) return m.group(1);
        }
        return null;
    }

    private String sha256Hex(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(data.hashCode());
        }
    }

    /**
     * IronWall v1.28.16: 设备指纹锁定。
     * 触发条件（任一）：
     * A) 该指纹随真实攻击请求命中并触发 IP 封禁（BLOCKED）；
     * B) 同一指纹在指纹MinIps 个不同 IP 上分别发起过真实攻击（跨代理池轮换证据）。
     * 防误封：登录态（trustedSession）一律不参与；爬虫/路径探测等噪声类型不参与；
     * 人机验证通过（releaseIdentity）或到期自动解除。
     */
    private void jailIdentity(String identity, String ip, String reason) {
        jailIdentity(identity, ip, reason, null);
    }

    /**
     * IronWall v1.43.0: uaHash 非空时锁定条目与 UA 联合判定——攻击者仅轮换自报指纹
     * 而保持同一浏览器 UA 仍被拦截；设备 ID 锁定（服务端签名，不可伪造）不附加 UA 条件。
     */
    private void jailIdentity(String identity, String ip, String reason, String uaHash) {
        if (!fingerprintEnabled || !isValidIdentityToken(identity)) return;
        try {
            long minutes = fingerprintBlockMinutes > 0 ? fingerprintBlockMinutes : 120;
            long now = System.currentTimeMillis();
            IdentityJail jail = identityJails.compute(identity, (k, old) -> {
                if (old == null || old.blockedUntil <= now) {
                    return new IdentityJail(now + minutes * 60_000L, uaHash);
                }
                old.blockedUntil = Math.max(old.blockedUntil, now + minutes * 60_000L);
                if (old.uaHash == null && uaHash != null) {
                    old.uaHash = uaHash;
                }
                old.ips.add(ip);
                return old;
            });
            if (jail.ips.isEmpty()) {
                jail.ips.add(ip);
            }
            String masked = identity.length() > 12 ? identity.substring(0, 12) + "..." : identity;
            persistLog(ip, TYPE_FINGERPRINT, reason + ":" + masked, "/", "system", "SYSTEM", 20, "BLOCKED");
            log.warn("[IronWall] IDENTITY JAILED: identity={} ip={} reason={}", masked, ip, reason);
        } catch (Exception e) {
            log.error("[IronWall] identity jail failed: {}", e.getMessage());
        }
    }

    /** 真实攻击计分时登记指纹来源 IP，跨 IP 证据达到阈值后联动锁定指纹。 */
    private void registerFingerprintSighting(String fp, String ip) {
        if (!fingerprintEnabled || fingerprintMinIps <= 1) return;
        if (!isValidIdentityToken(fp) || ip == null) return;
        if (!isPlausibleFingerprint(fp)) return;
        try {
            long windowMs = fingerprintWindowMinutes > 0 ? fingerprintWindowMinutes * 60_000L : 86_400_000L;
            long now = System.currentTimeMillis();
            FingerprintHit hit = fingerprintHits.computeIfAbsent(fp, k -> new FingerprintHit());
            if (now - hit.firstSeen > windowMs) {
                fingerprintHits.remove(fp, hit);
                FingerprintHit fresh = new FingerprintHit();
                FingerprintHit existing = fingerprintHits.putIfAbsent(fp, fresh);
                hit = existing != null ? existing : fresh;
            }
            hit.ips.add(ip);
            if (!hit.tripped && hit.ips.size() >= fingerprintMinIps) {
                hit.tripped = true;
                jailIdentity(fp, ip, "跨IP指纹协同锁定");
            }
        } catch (Exception e) {
            log.error("[IronWall] fingerprint sighting failed: {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.29.0: 设备级跨 IP 证据。
     * 攻击者随机化指纹头以规避指纹锁定时，设备ID（签名Cookie）仍可累积跨 IP 证据并锁定。
     * 仅真实攻击计分时登记；登录态与噪声类型不参与，正常设备换网络（WiFi/4G切换）零误伤。
     */
    private void registerDeviceSighting(String did, String ip) {
        if (!fingerprintEnabled || deviceMinIps <= 1) return;
        if (!isValidDeviceId(did) || ip == null) return;
        try {
            long windowMs = deviceWindowMinutes > 0 ? deviceWindowMinutes * 60_000L : 86_400_000L;
            long now = System.currentTimeMillis();
            FingerprintHit hit = deviceHits.computeIfAbsent(did, k -> new FingerprintHit());
            if (now - hit.firstSeen > windowMs) {
                deviceHits.remove(did, hit);
                FingerprintHit fresh = new FingerprintHit();
                FingerprintHit existing = deviceHits.putIfAbsent(did, fresh);
                hit = existing != null ? existing : fresh;
            }
            hit.ips.add(ip);
            if (!hit.tripped && hit.ips.size() >= deviceMinIps) {
                hit.tripped = true;
                jailIdentity(did, ip, "跨IP设备协同锁定");
            }
        } catch (Exception e) {
            log.error("[IronWall] device sighting failed: {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.29.0: 观察设备指纹并返回签名绑定。
     * 同一设备ID在窗口内更换 >= churn-min-fps 个不同指纹视为规避行为，直接锁定设备ID；
     * 正常浏览器指纹长期稳定（仅浏览器/系统升级时变化），不会误触发。
     */
    public String observeDeviceFingerprint(String did, String fp, String ip) {
        if (!fingerprintEnabled || !isValidDeviceId(did) || !isValidIdentityToken(fp)
                || !isPlausibleFingerprint(fp)) {
            return null;
        }
        try {
            long windowMs = fingerprintChurnWindowMinutes > 0 ? fingerprintChurnWindowMinutes * 60_000L : 3_600_000L;
            long now = System.currentTimeMillis();
            DeviceChurn churn = deviceFpChurn.computeIfAbsent(did, k -> new DeviceChurn());
            if (now - churn.firstSeen > windowMs) {
                deviceFpChurn.remove(did, churn);
                DeviceChurn fresh = new DeviceChurn();
                DeviceChurn existing = deviceFpChurn.putIfAbsent(did, fresh);
                churn = existing != null ? existing : fresh;
            }
            churn.fps.add(fp);
            if (!churn.tripped && fingerprintChurnMinFps > 0 && churn.fps.size() >= fingerprintChurnMinFps) {
                churn.tripped = true;
                jailIdentity(did, ip, "设备指纹轮换规避");
            }
        } catch (Exception e) {
            log.error("[IronWall] device fingerprint churn tracking failed: {}", e.getMessage());
        }
        return signFingerprintBinding(did, fp);
    }

    /** 指纹绑定签名：HMAC(did|fp)，防止伪造他人指纹或注入随机身份扰乱证据链。 */
    public String signFingerprintBinding(String did, String fp) {
        if (did == null || fp == null) return null;
        return hmacHex("fpbind:" + did + "|" + fp);
    }

    /** 校验指纹绑定签名（常量时间比较）。 */
    public boolean isValidFingerprintBinding(String did, String fp, String sig) {
        if (did == null || fp == null || sig == null || sig.length() < 16) return false;
        try {
            String expected = signFingerprintBinding(did, fp);
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    sig.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    /** 身份（fp 或 did）当前是否处于锁定状态；过期条目顺手回收。 */
    public boolean isIdentityJailed(String identity) {
        return isIdentityJailed(identity, null);
    }

    /**
     * IronWall v1.43.0: 带 UA 联合判定（指纹锁定专用）；
     * 设备 ID 锁定条目 uaHash 为 null，任意 UA 均命中。
     */
    public boolean isIdentityJailed(String identity, String uaHash) {
        if (!fingerprintEnabled || !isValidIdentityToken(identity)) return false;
        IdentityJail jail = identityJails.get(identity);
        if (jail == null) return false;
        if (jail.blockedUntil <= System.currentTimeMillis()) {
            identityJails.remove(identity, jail);
            return false;
        }
        if (jail.uaHash != null && !jail.uaHash.equals(uaHash)) {
            return false;
        }
        return true;
    }

    /** UA 指纹哈希（指纹锁定的联合判定信号；null 输入返回 null，等价任意匹配）。 */
    public String hashUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return null;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(userAgent.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** 身份锁定剩余秒数（未锁定返回 0）。 */
    public long identityJailRemainingSeconds(String identity) {
        if (!fingerprintEnabled || !isValidIdentityToken(identity)) return 0L;
        IdentityJail jail = identityJails.get(identity);
        if (jail == null) return 0L;
        long remainingMs = jail.blockedUntil - System.currentTimeMillis();
        if (remainingMs <= 0) {
            identityJails.remove(identity, jail);
            return 0L;
        }
        return remainingMs / 1000L;
    }

    /** 人机验证通过后释放身份锁（防误封逃生通道）。 */
    public void releaseIdentity(String identity) {
        if (!isValidIdentityToken(identity)) return;
        identityJails.remove(identity);
        fingerprintHits.remove(identity);
    }

    /** 签发服务端签名设备 ID：32 位随机 hex + "." + HMAC（防伪造）。 */
    public String issueDeviceId() {
        byte[] random = new byte[16];
        RANDOM.nextBytes(random);
        StringBuilder hex = new StringBuilder(32);
        for (byte b : random) {
            hex.append(String.format("%02x", b));
        }
        return hex + "." + hmacHex("did:" + hex);
    }

    /** 校验设备 ID 签名（常量时间比较，防时序侧信道）。 */
    public boolean isValidDeviceId(String did) {
        if (did == null) return false;
        int dot = did.indexOf('.');
        if (dot != 32) return false;
        String hex = did.substring(0, 32);
        if (!hex.matches("[0-9a-f]{32}")) return false;
        try {
            String expected = hmacHex("did:" + hex);
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    did.substring(dot + 1).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    /** 指纹/身份令牌格式：16-128 位 hex（前端 SHA-256 指纹或签名设备 ID）。 */
    private boolean isValidIdentityToken(String token) {
        if (token == null || token.length() < 16 || token.length() > 128) return false;
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.')) {
                return false;
            }
        }
        return true;
    }

    /**
     * IronWall v1.42.0: 自动化/伪造指纹识别（全零、单一重复字符、占位串）。
     * 仅剥夺身份信任与证据登记资格（不封禁、不记分），防止脚本用假指纹污染证据链或锁定无辜身份。
     */
    private boolean isPlausibleFingerprint(String fp) {
        if (fp == null) {
            return false;
        }
        String t = fp.trim();
        if (t.length() < 16) {
            return false;
        }
        char first = t.charAt(0);
        boolean allSame = true;
        boolean allZero = true;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c != first) {
                allSame = false;
            }
            if (c != '0') {
                allZero = false;
            }
        }
        if (allSame || allZero) {
            return false;
        }
        String lower = t.toLowerCase(Locale.ROOT);
        return !lower.startsWith("undefined") && !lower.startsWith("null");
    }

    public static final class Detection {
        public final String type;
        public final String payload;

        Detection(String type, String payload) {
            this.type = type;
            this.payload = payload;
        }
    }

    public static final class AttackRecord {
        public final String ip;
        public final String type;
        public final String payload;
        public final int score;
        public final int blockCount;
        public final long blockedUntil;
        public final String action;

        AttackRecord(String ip, String type, String payload, int score, int blockCount, long blockedUntil, String action) {
            this.ip = ip;
            this.type = type;
            this.payload = payload;
            this.score = score;
            this.blockCount = blockCount;
            this.blockedUntil = blockedUntil;
            this.action = action;
        }
    }

    // IronWall v1.28.15: 同载荷指纹的跨IP来源登记结构
    private static final class CampaignHit {
        final Set<String> ips = ConcurrentHashMap.newKeySet();
        volatile long firstSeen = System.currentTimeMillis();
        volatile boolean tripped;
    }

    // IronWall v1.28.16: 身份（设备指纹/设备ID）锁定状态
    private static final class IdentityJail {
        final Set<String> ips = ConcurrentHashMap.newKeySet();
        volatile String uaHash;
        volatile long blockedUntil;

        IdentityJail(long blockedUntil, String uaHash) {
            this.blockedUntil = blockedUntil;
            this.uaHash = uaHash;
        }
    }

    // IronWall v1.28.16: 同一指纹跨 IP 攻击证据累积
    private static final class FingerprintHit {
        final Set<String> ips = ConcurrentHashMap.newKeySet();
        volatile long firstSeen = System.currentTimeMillis();
        volatile boolean tripped;
    }

    // IronWall v1.33.0: 相似模板聚合桶（字符 n-gram 集合 + 成员 IP）
    private static final class SimilarTemplateHit {
        final Set<String> grams;
        final String template;
        final Set<String> ips = ConcurrentHashMap.newKeySet();
        volatile long firstSeen = System.currentTimeMillis();
        volatile boolean tripped;

        SimilarTemplateHit(Set<String> grams, String template) {
            this.grams = grams;
            this.template = template;
        }
    }

    // IronWall v1.29.0: 设备ID下观察到的指纹集合（轮换过快判定规避）
    private static final class DeviceChurn {
        final Set<String> fps = ConcurrentHashMap.newKeySet();
        volatile long firstSeen = System.currentTimeMillis();
        volatile boolean tripped;
    }

    public static final class IpState {
        volatile int score;
        volatile int blockCount;
        volatile long blockedUntil;
        volatile long lastSeen = System.currentTimeMillis();
        volatile String lastSignature;
        volatile long lastSignatureTime;
        volatile boolean toolSeen;
        // IronWall v1.24.0: 人机验证失败计数（10 分钟滑动窗口）与服务器级升级标记
        volatile int challengeFails;
        volatile long challengeFailWindowStart;
        volatile boolean challengeEscalated;

    }

    // IronWall v1.24.0: 人机验证挑战令牌（服务端状态，5 分钟有效）
    public static final class ChallengeEntry {
        final String ip;
        final String question;
        final int answer;
        final long expiresAt;

        ChallengeEntry(String ip, String question, int answer, long expiresAt) {
            this.ip = ip;
            this.question = question;
            this.answer = answer;
            this.expiresAt = expiresAt;
        }
    }

    public static final class SegmentState {
        volatile String segment;
        volatile long blockedUntil;
        volatile int blockCount;

        SegmentState(String segment, long blockedUntil, int blockCount) {
            this.segment = segment;
            this.blockedUntil = blockedUntil;
            this.blockCount = blockCount;
        }
    }

    public static final class SegmentInfo {
        public final String segment;
        public final int blockCount;
        public final long blockedUntil;
        public final long blockedSeconds;

        SegmentInfo(String segment, int blockCount, long blockedUntil, long blockedSeconds) {
            this.segment = segment;
            this.blockCount = blockCount;
            this.blockedUntil = blockedUntil;
            this.blockedSeconds = blockedSeconds;
        }
    }

    // IronWall v1.17.1: SUSPECT=低分可疑（记分>0 但未达扫描/顽固级别）
    public enum ThreatProfile { UNKNOWN, SUSPECT, SCANNER, PERSISTENT, TARGETED }

    public static final class BlockInfo {
        public final String ip;
        public final int score;
        public final int blockCount;
        public final long blockedUntil;
        public final long blockedSeconds;


        BlockInfo(String ip, int score, int blockCount, long blockedUntil, long blockedSeconds) {
            this.ip = ip;
            this.score = score;
            this.blockCount = blockCount;
            this.blockedUntil = blockedUntil;
            this.blockedSeconds = blockedSeconds;

        }
    }

    public boolean isBlocked(String ip) {
        IpState state = ipStates.get(ip);
        return state != null && state.blockedUntil > System.currentTimeMillis();
    }

    // IronWall v1.47.2: 返回真实剩余封禁秒数（未封禁返回 0），
    // 供 TarpitFilter 下发与事实一致的 Retry-After（修复「提示 1 分钟实际 ≥15 分钟)。
    public long blockRemainingSeconds(String ip) {
        IpState state = ip == null ? null : ipStates.get(ip);
        if (state == null) {
            return 0L;
        }
        long remainingMs = state.blockedUntil - System.currentTimeMillis();
        return remainingMs > 0 ? Math.max(1L, (remainingMs + 999L) / 1000L) : 0L;
    }

    public void unblock(String ip) {
        ipStates.remove(ip);
        persistSyncEvent(ip, "UNBLOCKED", 0L);
    }

    /**
     * IronWall v1.39.0: multipart 误封精确补偿。
     * 只解封满足全部条件的 IP：72 小时窗口内流水全部为「NULL字节截断」且路径命中
     * 上传端点（multipart 误报签名）；窗口内存在任何其他攻击类型则保留封禁。
     * 证据流水不删；任何异常 fail-open（跳过该 IP），绝不扩大解封面。
     */
    public List<String> purgeUploadFalsePositives() {
        List<String> purged = new ArrayList<>();
        long windowStart = System.currentTimeMillis() - 72 * 3600_000L;
        for (String ip : new ArrayList<>(ipStates.keySet())) {
            try {
                List<AttackLog> logs = attackLogRepository.findTop100ByIpOrderByCreatedAtDesc(ip);
                if (logs == null || logs.isEmpty()) {
                    continue;
                }
                boolean onlyFalsePositive = false;
                for (AttackLog log : logs) {
                    LocalDateTime created = log.getCreatedAt();
                    if (created == null) {
                        continue;
                    }
                    long at = created.atZone(java.time.ZoneId.systemDefault())
                            .toInstant().toEpochMilli();
                    if (at < windowStart) {
                        continue;
                    }
                    if (isUploadFalsePositive(log)) {
                        onlyFalsePositive = true;
                    } else {
                        onlyFalsePositive = false;
                        break;
                    }
                }
                if (!onlyFalsePositive) {
                    continue;
                }
                ipStates.remove(ip);
                persistSyncEvent(ip, "UNBLOCKED", 0L);
                purged.add(ip);
            } catch (Exception e) {
                log.warn("[IronWall] purge upload false positive failed for ip={}: {}", ip, e.getMessage());
            }
        }
        return purged;
    }

    /** IronWall v1.39.0: multipart 误报签名 = NULL字节截断 + 上传端点路径。 */
    private boolean isUploadFalsePositive(AttackLog log) {
        if (log == null || !"NULL字节截断".equals(log.getPayload())) {
            return false;
        }
        String path = log.getPath();
        return path != null && UPLOAD_PATH.matcher(path.replaceFirst("\\?.*$", "")).find();
    }

    /** IronWall v1.38.0: 合并远端实例的封禁（取较晚到期，不清记分、不二次桥接、不回写事件）。 */
    public void applyRemoteBan(String ip, long blockedUntil) {
        if (ip == null || blockedUntil <= System.currentTimeMillis()) {
            return;
        }
        IpState state = ipStates.computeIfAbsent(ip.trim(), k -> new IpState());
        synchronized (state) {
            state.blockedUntil = Math.max(state.blockedUntil, blockedUntil);
        }
    }

    /** IronWall v1.38.0: 合并远端实例的解封（保留记分，与本地解封语义一致）。 */
    public void applyRemoteUnblock(String ip) {
        if (ip == null) {
            return;
        }
        IpState state = ipStates.get(ip.trim());
        if (state != null) {
            synchronized (state) {
                state.blockedUntil = 0L;
            }
        }
    }

    public boolean isSelfInstance(String instanceTag) {
        return instanceTag != null && instanceTag.equals("instance:" + instanceId());
    }

    /** IronWall v1.38.0: 写封禁同步事件（失败仅日志，绝不影响封禁主链）。 */
    private void persistSyncEvent(String ip, String action, long blockedUntil) {
        if (ip == null || ip.isBlank() || !enabled) {
            return;
        }
        try {
            AttackLog event = new AttackLog();
            event.setIp(ip.trim());
            event.setAttackType(TYPE_SYNC);
            event.setPath("/api/ban-sync");
            event.setPayload(String.valueOf(blockedUntil));
            event.setUserAgent("instance:" + instanceId());
            event.setMethod("SYSTEM");
            event.setScore(SCORE_SEVERE);
            event.setAction(action == null ? "BLOCKED" : action);
            attackLogRepository.save(event);
        } catch (Exception e) {
            log.warn("[IronWall] ban sync event persist failed: {}", e.getMessage());
        }
    }

    /** IronWall v1.38.1: stable instance id = host|port|app fingerprint (restart-safe self-loop skip). */
    private String instanceId() {
        String id = instanceId;
        if (id == null) {
            synchronized (this) {
                id = instanceId;
                if (id == null) {
                    String host = "host";
                    try {
                        host = java.net.InetAddress.getLocalHost().getHostName();
                    } catch (Exception ignored) {
                        // keep fallback host label
                    }
                    String seed = host + "|" + serverPort + "|" + (appName == null ? "jdy-cloud" : appName);
                    id = "instance:" + sha256Hex(seed).substring(0, 16);
                    instanceId = id;
                }
            }
        }
        return id;
    }

    private void notifyAlert(String type, String ip, String detail) {
        AlertNotifierService notifier = alertNotifier;
        if (notifier != null) {
            try {
                notifier.notify(type, ip, detail);
            } catch (Exception e) {
                log.warn("[IronWall] alert notify failed: {}", e.getMessage());
            }
        }
    }

    // ========== IronWall v1.24.0: 人机验证二次确认挑战 ==========

    public boolean isChallengeEnabled() {
        return challengeEnabled;
    }

    /**
     * 为被封禁 IP 签发一次性人机验证挑战。
     * @return "token|question"；不可用（未启用/未封禁/网段封禁）时返回 null
     */
    public String issueChallenge(String ip) {
        if (!challengeEnabled || ip == null || isBlockedSegment(ip)) {
            return null;
        }
        int a = 7 + RANDOM.nextInt(90);
        int b = 7 + RANDOM.nextInt(90);
        // IronWall v1.26.2: token 改为 HMAC 签名并内嵌过期时间，伪造/篡改/跨 IP 复用一律拒绝
        long expiresAt = System.currentTimeMillis() + CHALLENGE_TTL_MS;
        String token = signChallengeToken(UUID.randomUUID().toString().replace("-", ""), expiresAt, ip.trim());
        challenges.put(token, new ChallengeEntry(ip.trim(), a + " + " + b + " = ?", a + b,
                expiresAt));
        return token + "|" + a + " + " + b + " = ?";
    }

    /**
     * 校验人机验证答案。返回 null 表示通过并已解除站内封禁；
     * 返回 answer_wrong / expired / locked / not_eligible 表示失败原因。
     * 记分保留：解封后再犯一击即重新封禁，并按再犯升级服务器级全端口封禁。
     */
    public String verifyChallenge(String ip, String token, String answer) {
        if (!challengeEnabled || ip == null || isBlockedSegment(ip)) {
            return "not_eligible";
        }
        String normalized = ip.trim();
        IpState state = ipStates.get(normalized);
        if (state == null) {
            return "not_eligible";
        }
        long now = System.currentTimeMillis();
        int maxAttempts = challengeMaxAttempts > 0 ? challengeMaxAttempts : 5;
        synchronized (state) {
            if (now - state.challengeFailWindowStart > CHALLENGE_ATTEMPT_WINDOW_MS) {
                state.challengeFailWindowStart = now;
                state.challengeFails = 0;
            }
            if (state.challengeFails >= maxAttempts) {
                // 挑战滥用 = 高置信自动化攻击：升级服务器层全端口封禁（只触发一次）
                if (!state.challengeEscalated) {
                    state.challengeEscalated = true;
                    if (fail2banBridgeEnabled) {
                        F2B_LOG.info("IRONWALL-BLOCK ip={} category=CHALLENGE_ABUSE score={} action=BLOCKED", normalized, state.score);
                    }
                    persistLog(normalized, TYPE_TRAP, "人机验证失败次数超限，升级服务器级全端口封禁",
                            "/api/blocked-page/verify", "blocked-page", "POST", state.score, "ESCALATED");
                    notifyAlert(TYPE_TRAP, normalized, "人机验证失败次数超限，升级服务器级全端口封禁");
                }
                return "locked";
            }
            ChallengeEntry entry = token == null ? null : challenges.get(token);
            if (entry == null || !entry.ip.equals(normalized) || entry.expiresAt <= now
                    || !isValidChallengeToken(token, normalized)) {
                state.challengeFails++;
                if (entry != null) {
                    challenges.remove(token);
                }
                return "expired";
            }
            if (answer == null || !answer.trim().equals(String.valueOf(entry.answer))) {
                state.challengeFails++;
                challenges.remove(token);
                return "answer_wrong";
            }
            challenges.remove(token);
            // 二次确认通过：解除站内封禁但保留记分——再犯立即重新封禁并升级服务器级封禁
            state.blockedUntil = 0;
            state.challengeFails = 0;
            state.challengeFailWindowStart = now;
            state.challengeEscalated = false;
            persistLog(normalized, "人机验证", "二次确认通过，自动解除站内封禁（再犯立即升级处置）",
                    "/api/blocked-page/verify", "blocked-page", "POST", state.score, "UNBLOCKED_CHALLENGE");
            return null;
        }
    }

    /** IronWall v1.26.2: high-risk attack type check (SQL/XSS/traversal/command/SSRF). */
    public boolean isHighRiskAttackType(String type) {
        return TYPE_SQL.equals(type) || TYPE_XSS.equals(type) || TYPE_TRAVERSAL.equals(type)
                || TYPE_CMD.equals(type) || TYPE_SSRF.equals(type);
    }

    /**
     * IronWall v1.37.0: 计分分级单点映射。
     * 协议异常/路径探测 2 分、爬虫 1 分（保留）、SSRF 3 分（中置信保留）、
     * 其余明确攻击 5 分；陷阱/蜜罐级高危由 TrapService 以 SCORE_SEVERE=20 直接投分。
     */
    public int pointsFor(String type) {
        if (TYPE_PROTOCOL.equals(type) || TYPE_SUSPICIOUS_PATH.equals(type)) {
            return SCORE_NOISE;
        }
        if (TYPE_CRAWLER.equals(type)) {
            return SCORE_CRAWLER;
        }
        if (TYPE_SSRF.equals(type)) {
            return SCORE_SSRF;
        }
        return SCORE_ATTACK;
    }

    /**
     * IronWall v1.28.15: 仅真实攻击类型参与跨IP协同指纹登记；
     * 爬虫/路径探测/协议异常等噪声类型不参与，规避 NAT 与预取流量误伤。
     */
    private boolean isRealAttackType(String type) {
        return isHighRiskAttackType(type) || TYPE_TOOL.equals(type) || TYPE_HONEYPOT.equals(type);
    }

    /** IronWall v1.26.2: challenge token = nonce.exp.hmac(ip|nonce|exp), HMAC-signed and expiring. */
    private String signChallengeToken(String nonce, long expiresAt, String ip) {
        return nonce + "." + expiresAt + "." + hmacHex(ip + "|" + nonce + "|" + expiresAt);
    }

    /** IronWall v1.26.2: constant-time token signature and expiry validation. */
    private boolean isValidChallengeToken(String token, String ip) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }
            long expiresAt = Long.parseLong(parts[1]);
            if (expiresAt <= System.currentTimeMillis()) {
                return false;
            }
            String expected = signChallengeToken(parts[0], expiresAt, ip);
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(challengeKeyBytes(), "HmacSHA256"));
            byte[] out = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("hmac failure", e);
        }
    }

    private byte[] challengeKeyBytes() {
        String key = challengeKey;
        if (key == null) {
            synchronized (this) {
                key = challengeKey;
                if (key == null) {
                    key = (challengeSecret == null || challengeSecret.isBlank())
                            ? UUID.randomUUID().toString() : challengeSecret;
                    challengeKey = key;
                }
            }
        }
        return key.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * IronWall v1.24.0: 单发即封的普通攻击类型不立即联动服务器层全端口封禁，
     * 改为站内封禁 + 人机验证二次确认，避免误伤真实用户；
     * 蜜罐/陷阱等高置信类型与累积/再犯封禁直接联动。
     */
    private boolean shouldBridgeOnBlock(String type, boolean singleHitBlock) {
        if (TYPE_TRAP.equals(type) || TYPE_HONEYPOT.equals(type)) {
            return true;
        }
        return !singleHitBlock;
    }
    /**
     * IronWall v1.17.3: 管理员面板一键手动封禁 IP。
     * 手动封禁为管理员决策，直接按指定分钟数（1 分钟 ~ 7 天）生效；
     * 不参与段封禁升级，避免误伤同段正常用户。
     */
    public AttackRecord manualBlock(String ip, int minutes) {
        String normalized = ip == null ? "" : ip.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("IP cannot be empty");
        }
        long effectiveMinutes = Math.max(1, Math.min(minutes, 7 * 24 * 60));
        int floorScore = blockScore > 0 ? blockScore : 20;
        IpState state = ipStates.computeIfAbsent(normalized, k -> new IpState());
        synchronized (state) {
            long now = System.currentTimeMillis();
            state.blockedUntil = Math.max(state.blockedUntil, now + effectiveMinutes * 60_000L);
            state.blockCount++;
            state.score = Math.max(state.score, floorScore);
            persistLog(normalized, TYPE_TOOL, "管理员手动封禁 " + effectiveMinutes + " 分钟",
                    "/api/admin/security/block-ip", "admin-panel", "SYSTEM", state.score, "BLOCKED");
            persistSyncEvent(normalized, "BLOCKED", state.blockedUntil);
            if (fail2banBridgeEnabled) {
                F2B_LOG.info("IRONWALL-BLOCK ip={} category=MANUAL_BLOCK score={} action=BLOCKED", normalized, state.score);
            }
            notifyAlert(TYPE_TOOL, normalized, "管理员手动封禁 " + effectiveMinutes + " 分钟");
            return new AttackRecord(normalized, TYPE_TOOL, "manual-block", state.score,
                    state.blockCount, state.blockedUntil, "BLOCKED");
        }
    }

    public List<BlockInfo> getBlockedIps() {
        long now = System.currentTimeMillis();
        List<BlockInfo> list = new ArrayList<>();
        for (Map.Entry<String, IpState> e : ipStates.entrySet()) {
            IpState st = e.getValue();
            if (st.blockedUntil > now) {
                list.add(new BlockInfo(e.getKey(), st.score, st.blockCount, st.blockedUntil,
                        Math.max(0, (st.blockedUntil - now) / 1000)));
            }
        }
        list.sort(Comparator.comparingLong(b -> -b.blockedUntil));
        return list;
    }

    public boolean isBlockedSegment(String ip) {
        String segment = segmentOf(ip);
        if (segment == null) return false;
        SegmentState state = segmentStates.get(segment);
        return state != null && state.blockedUntil > System.currentTimeMillis();
    }

    public List<SegmentInfo> getBlockedSegments() {
        long now = System.currentTimeMillis();
        List<SegmentInfo> list = new ArrayList<>();
        for (SegmentState st : segmentStates.values()) {
            if (st.blockedUntil > now) {
                list.add(new SegmentInfo(st.segment, st.blockCount, st.blockedUntil,
                        Math.max(0, (st.blockedUntil - now) / 1000)));
            }
        }
        list.sort(Comparator.comparingLong(s -> -s.blockedUntil));
        return list;
    }

    public void unblockSegment(String segment) {
        if (segment == null) return;
        segmentStates.remove(segment.trim());
    }

    /**
     * IronWall v1.17: 攻击者一旦记分达到警告线或被封禁，进入 Tarpit 拖延名单，
     * 由 TarpitFilter 对其后续请求进行限速拖延消耗，不消耗正常用户资源。
     */
    public boolean shouldTarpit(String ip) {
        IpState state = ipStates.get(ip);
        if (state == null) return false;
        long now = System.currentTimeMillis();
        return state.blockedUntil > now || state.score >= (warnScore > 0 ? warnScore : 10);
    }

    public ThreatProfile classifyThreat(String ip) {
        IpState state = ipStates.get(ip);
        if (state == null) return ThreatProfile.UNKNOWN;
        int severe = severeBlockScore > 0 ? severeBlockScore : 40;
        int block = blockScore > 0 ? blockScore : 20;
        if (state.score >= severe) return ThreatProfile.TARGETED;
        if (state.score >= block) return ThreatProfile.PERSISTENT;
        if (state.toolSeen) return ThreatProfile.SCANNER;
        if (state.score > 0) return ThreatProfile.SUSPECT;
        return ThreatProfile.UNKNOWN;
    }

    public List<Map<String, Object>> getAttackerSummaries() {
        List<Map<String, Object>> list = new ArrayList<>();
        long now = System.currentTimeMillis();
        for (Map.Entry<String, IpState> e : ipStates.entrySet()) {
            IpState st = e.getValue();
            if (st.score <= 0) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", e.getKey());
            m.put("score", st.score);
            m.put("block_count", st.blockCount);
            m.put("blocked_until", st.blockedUntil);
            m.put("tool_seen", st.toolSeen);
            m.put("tarpit", shouldTarpit(e.getKey()));
            m.put("segment_blocked", isBlockedSegment(e.getKey()));
            m.put("threat_profile", classifyThreat(e.getKey()).name());
            m.put("last_seen", LocalDateTime.ofInstant(
                    java.time.Instant.ofEpochMilli(st.lastSeen), java.time.ZoneId.systemDefault()).toString());
            list.add(m);
        }
        list.sort((a, b) -> Integer.compare((int) b.get("score"), (int) a.get("score")));
        return list;
    }

    /**
     * 扫描请求文本，命中攻击特征返回 Detection，否则 null。
     */
    public Detection detect(String queryString, String body, String uri, String userAgent) {
        return detect(queryString, body, uri, userAgent, null);
    }

    /**
     * IronWall v1.10: also scores XSS/SQLi payloads carried in User-Agent / Referer headers.
     */
    public Detection detect(String queryString, String body, String uri, String userAgent, String referer) {
        return detect(queryString, body, uri, userAgent, referer, null);
    }

    /**
     * IronWall v1.12: also scores XSS payloads carried in the Cookie header
     * (XSS only to keep false-positive surface low for session tokens).
     */
    public Detection detect(String queryString, String body, String uri, String userAgent, String referer, String cookieHeader) {
        if (!enabled) return null;
        StringBuilder sb = new StringBuilder();
        if (uri != null) sb.append(uri).append(' ');
        if (queryString != null) sb.append(queryString).append(' ');
        if (body != null) sb.append(body).append(' ');

        String raw = sb.toString();
        String decoded = safeDecode(raw);
        String doubleDecoded = safeDecode(decoded);
        // IronWall v1.28.15: NULL 字节在正常业务中不合法，统一按路径穿越拒绝（%00/%2500 截断变体）
        if (raw.indexOf('\u0000') >= 0 || decoded.indexOf('\u0000') >= 0 || doubleDecoded.indexOf('\u0000') >= 0) {
            return new Detection(TYPE_TRAVERSAL, "NULL字节截断");
        }
        String normalized = normalizeForScan(decoded);
        String full = raw + "\n" + decoded + "\n" + doubleDecoded + "\n" + normalized;

        Detection det = match(SQLI, TYPE_SQL, full);
        if (det != null) return det;
        det = match(SQLI_OPERATOR, TYPE_SQL, full);
        if (det != null) return det;
        if (operatorFamilyEnabled) {
            det = match(SQLI_OPERATOR_FAMILY, TYPE_SQL, full);
            if (det != null) return det;
        }
        if (mysqlBuiltinEnabled) {
            det = match(SQLI_MYSQL_BUILTIN, TYPE_SQL, full);
            if (det != null) return det;
        }
        // IronWall v1.31.0: 正则层未命中时运行 SQL 语义层（结构判定，第二意见）
        if (semanticEnabled) {
            String semantic = semanticAnalyzer.findSql(full);
            if (semantic != null) return new Detection(TYPE_SQL, semantic);
        }
        det = match(SQLI_HEX, TYPE_SQL, full);
        if (det != null) return det;
        det = match(XSS, TYPE_XSS, full);
        if (det != null) return det;
        det = match(TRAVERSAL, TYPE_TRAVERSAL, full);
        if (det != null) return det;
        det = match(CMD, TYPE_CMD, full);
        if (det != null) return det;
        det = match(SSRF, TYPE_SSRF, full);
        if (det != null) return det;

        // IronWall v1.7: 路径异常（;.js / 双扩展名等）单独归类，低分计分
        if (uri != null) {
            det = match(SUSPICIOUS_PATH, TYPE_SUSPICIOUS_PATH, uri);
            if (det != null) return det;
        }

        if (userAgent != null) {
            det = match(TOOL_UA, TYPE_TOOL, userAgent);
            if (det != null) return det;
        }
        // IronWall v1.10: UA/Referer header payload scoring (XSS/SQLi only, low false-positive surface)
        String headerText = (userAgent == null ? "" : userAgent) + "\n" + (referer == null ? "" : referer);
        if (!headerText.isBlank()) {
            det = match(XSS, TYPE_XSS, headerText);
            if (det != null) return det;
            det = match(SQLI, TYPE_SQL, headerText);
            if (det != null) return det;
        }
        // IronWall v1.12: Cookie 头 XSS 载荷检测
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            det = match(XSS, TYPE_XSS, cookieHeader);
            if (det != null) return det;
        }
        return null;
    }

    /**
     * IronWall v1.5 E-01: 归一化扫描
     * 1) JSON Unicode 转义解码（U+003C -> <、U+0027 -> 单引号）
     * 2) SQL 内联注释分割归一化（UN-注释-ION -> UNION）
     */
    /**
     * IronWall v1.11: 判断 UA 是否属于自动化爬虫/脚本客户端。
     */
    public static boolean isCrawlerUa(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return false;
        if (userAgent.startsWith("Mozilla/") || userAgent.contains("Chrome/") || userAgent.contains("Firefox/")
                || userAgent.contains("Safari/") || userAgent.contains("Edg/")) {
            return false;
        }
        return CRAWLER_UA.matcher(userAgent).find();
    }

    private String normalizeForScan(String input) {
        if (input == null || input.isEmpty()) return input;
        // IronWall v1.33.0: 替换串一律 quoteReplacement（裸反斜杠会被 appendReplacement 当转义符抛异常），
        // 解码任何异常回退原始文本——归一化绝不 fail-open。
        String out;
        try {
            out = JSON_UNICODE_ESCAPE.matcher(input).replaceAll(mr -> {
                try {
                    int codePoint = Integer.parseInt(mr.group(1), 16);
                    if (Character.isValidCodePoint(codePoint)) {
                        return Matcher.quoteReplacement(new String(Character.toChars(codePoint)));
                    }
                } catch (NumberFormatException ignored) { }
                return Matcher.quoteReplacement(mr.group());
            });
        } catch (Exception e) {
            out = input;
        }
        // IronWall v1.28.15: JSON 字符串转义解码（\t \n \r \f \b -> 空白，\" \' \\ \/ -> 字面字符）
        String jsonEsc;
        try {
            jsonEsc = JSON_STRING_ESCAPE.matcher(out).replaceAll(mr -> {
                switch (mr.group(1)) {
                    case "t": case "n": case "r": case "f": case "b": return " ";
                    default: return Matcher.quoteReplacement(mr.group(1));
                }
            });
        } catch (Exception e) {
            jsonEsc = out;
        }
        // IronWall v1.28.15: NFKC 全角归一化（全角字母 -> ASCII），仅用于扫描不落库
        String nfkc;
        try {
            nfkc = Normalizer.normalize(jsonEsc, Normalizer.Form.NFKC);
        } catch (Exception e) {
            nfkc = jsonEsc;
        }
        String removed = SQL_INLINE_COMMENT.matcher(nfkc).replaceAll("");
        String spaced = SQL_INLINE_COMMENT.matcher(nfkc).replaceAll(" ");
        String wsNormalized = UNICODE_WS.matcher(removed).replaceAll(" ");
        String wsAll = wsNormalized.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
        // IronWall v1.30.0: 双写递归清洗 + 引号族归一化变体（仅扫描不落库）
        String dedup = dedupDoubleWrite(jsonEsc);
        String noBackslash = jsonEsc.replace("\\", "");
        String noBacktick = jsonEsc.replace("`", "");
        String quoteNorm = jsonEsc.replace('"', '\'').replace('`', '\'');
        return removed + "\n" + spaced + "\n" + wsNormalized + "\n" + wsAll + "\n" + nfkc + "\n" + jsonEsc
                + "\n" + dedup + "\n" + noBackslash + "\n" + noBacktick + "\n" + quoteNorm;
    }

    /**
     * 双写关键词还原对照表由外部规则文件提供（{@code normalization.doubleWriteMap}）。
     *
     * <p>表为空时本归一化层自动停用，不影响其余检测。
     */
    private static final Map<String, String> DOUBLE_WRITE_MAP =
            IronWallRules.map("normalization.doubleWriteMap");

    /** IronWall v1.30.0: 双写关键词递归清洗（OORR→OR 等），词界锚定，收敛即止。 */
    private String dedupDoubleWrite(String input) {
        if (input == null || input.isEmpty()) return input;
        String out = input;
        for (int i = 0; i < 5; i++) {
            String next = DOUBLE_WRITE_TOKEN.matcher(out).replaceAll(mr -> {
                String collapsed = DOUBLE_WRITE_MAP.get(mr.group(1).toLowerCase(Locale.ROOT));
                return collapsed != null ? collapsed : mr.group();
            });
            if (next.equals(out)) break;
            out = next;
        }
        return out;
    }

    private Detection match(Pattern pattern, String type, String input) {
        Matcher m = pattern.matcher(input);
        if (m.find()) {
            String snippet = input.substring(Math.max(0, m.start() - 40),
                    Math.min(input.length(), m.end() + 80));
            return new Detection(type, snippet.trim());
        }
        return null;
    }

    private String safeDecode(String input) {
        try {
            return URLDecoder.decode(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return input;
        }
    }

    /**
     * 记录一次攻击并更新 IP 记分/封禁状态。
     */
    public AttackRecord recordAttack(String ip, String type, String payload, String path, String userAgent, String method) {
        return recordAttack(ip, type, payload, path, userAgent, method, false);
    }

    /**
     * IronWall v1.15: trustedSession=true means the request carries a valid user/admin
     * JWT. Such requests are logged but never accumulate score and never escalate to an IP
     * block, so routine authenticated operations can never lock a user (or the whole NAT IP)
     * out of the platform. Attack payloads are still rejected upstream with a 4440 warning.
     */
    public AttackRecord recordAttack(String ip, String type, String payload, String path, String userAgent, String method, boolean trustedSession) {
        return recordAttack(ip, type, payload, path, userAgent, method, trustedSession, 0);
    }

    /**
     * IronWall v1.32.0: 尾参 extraWeight 在默认记分之上叠加（代理/机房信誉放大器专用）。
     * 仅真实攻击调用方使用；登录态请求恒不加分。旧签名全部委托本重载（extraWeight=0），行为不变。
     */
    public AttackRecord recordAttack(String ip, String type, String payload, String path, String userAgent,
                                     String method, boolean trustedSession, int extraWeight) {
        // IronWall v1.37.0: 计分分级单点映射（协议异常/探测 2、爬虫 1、SSRF 3、明确攻击 5）
        int defaultDelta = trustedSession ? 0 : pointsFor(type);
        // IronWall v1.26.2: 登录/上传/管理端等高危路径对真实攻击类型差异化阈值（2 击即封），普通路径保持宽容度
        if (!trustedSession && defaultDelta > 0 && isHighRiskAttackType(type)
                && HIGH_RISK_PATH.matcher(path == null ? "" : path).find()) {
            defaultDelta = Math.max(defaultDelta, highRiskPathWeight > 0 ? highRiskPathWeight : 10);
        }
        int weight = trustedSession ? 0 : Math.max(0, defaultDelta) + Math.max(0, extraWeight);
        return recordWeighted(ip, type, payload, path, userAgent, method, trustedSession, weight);
    }

    /**
     * IronWall v1.28.16: 携带设备指纹/设备ID 的攻击记分。
     * 真实攻击触发 IP 封禁的瞬间联动锁定身份，换代理 IP 后同样被拦截。
     */
    public AttackRecord recordAttack(String ip, String type, String payload, String path, String userAgent,
                                     String method, boolean trustedSession, String fingerprint, String deviceId) {
        return recordAttack(ip, type, payload, path, userAgent, method, trustedSession, fingerprint, deviceId, null, 0);
    }

    /** IronWall v1.29.0: 携带指纹绑定签名，防随机化/伪造指纹身份。 */
    public AttackRecord recordAttack(String ip, String type, String payload, String path, String userAgent,
                                     String method, boolean trustedSession, String fingerprint, String deviceId,
                                     String fingerprintSignature) {
        return recordAttack(ip, type, payload, path, userAgent, method, trustedSession, fingerprint, deviceId,
                fingerprintSignature, 0);
    }

    /**
     * IronWall v1.32.0: 指纹携带 + 放大叠加重载（代理/机房信誉放大器专用）。
     * extraWeight 仅追加到真实攻击记分；登录态请求恒不加分。
     */
    public AttackRecord recordAttack(String ip, String type, String payload, String path, String userAgent,
                                     String method, boolean trustedSession, String fingerprint, String deviceId,
                                     String fingerprintSignature, int extraWeight) {
        int defaultDelta = trustedSession ? 0 : pointsFor(type);
        if (!trustedSession && defaultDelta > 0 && isHighRiskAttackType(type)
                && HIGH_RISK_PATH.matcher(path == null ? "" : path).find()) {
            defaultDelta = Math.max(defaultDelta, highRiskPathWeight > 0 ? highRiskPathWeight : 10);
        }
        int weight = trustedSession ? 0 : Math.max(0, defaultDelta) + Math.max(0, extraWeight);
        return recordWeighted(ip, type, payload, path, userAgent, method, trustedSession, weight,
                fingerprint, deviceId, fingerprintSignature);
    }

    /**
     * IronWall v1.20 银行级加权记分：蜜罐/主动防御链按层递进加权，
     * 允许调用方显式指定单次击打分值（蜜罐 L1=5、L2=10、L3=15、L4=20、L5=40）。
     */
    public AttackRecord recordWeighted(String ip, String type, String payload, String path, String userAgent, String method, boolean trustedSession, int weight) {
        return recordWeighted(ip, type, payload, path, userAgent, method, trustedSession, weight, null, null);
    }

    /** IronWall v1.29.0: 身份感知记分主链（fp/did/sig 可选，旧调用方保持不变）。 */
    public AttackRecord recordWeighted(String ip, String type, String payload, String path, String userAgent,
                                       String method, boolean trustedSession, int weight, String fingerprint, String deviceId) {
        return recordWeighted(ip, type, payload, path, userAgent, method, trustedSession, weight,
                fingerprint, deviceId, null);
    }

    public AttackRecord recordWeighted(String ip, String type, String payload, String path, String userAgent,
                                       String method, boolean trustedSession, int weight, String fingerprint,
                                       String deviceId, String fingerprintSignature) {
        int effectiveBlockScore = blockScore > 0 ? blockScore : 20;
        int effectiveSevereScore = severeBlockScore > 0 ? severeBlockScore : 40;
        int effectiveBlockMinutes = blockMinutes > 0 ? blockMinutes : 30;
        int effectiveSevereHours = severeBlockHours > 0 ? severeBlockHours : 24;
        IpState state = ipStates.computeIfAbsent(ip, k -> new IpState());
        int delta = trustedSession ? 0 : Math.max(0, weight);
        // IronWall v1.29.0: 有设备ID时必须携带有效绑定签名才信任指纹；
        // 无设备ID（旧客户端/直连脚本）时指纹仍可用（其唯一身份，锁错也只锁攻击者自己）。
        boolean fingerprintTrusted = fingerprint != null && isPlausibleFingerprint(fingerprint)
                && (deviceId == null || isValidFingerprintBinding(deviceId, fingerprint, fingerprintSignature));
        // IronWall v1.28.15: 真实攻击记分同步登记跨IP协同指纹（登录态不参与，避免误伤）
        if (delta > 0) {
            registerCampaignHit(type, payload, ip);
            // IronWall v1.28.16: 仅真实攻击类型登记跨 IP 指纹证据（噪声类型不参与）
            if (isRealAttackType(type)) {
                // IronWall v1.30.0: 攻击族×路径跨IP聚合（真实攻击才登记）
                registerAttackFamilyHit(type, path, ip);
                // IronWall v1.32.0: 攻击模板×路径跨IP聚合（字面量漂移归一再联动封禁）
                registerTemplateHit(type, path, payload, ip);
                if (deviceId != null) {
                    registerDeviceSighting(deviceId, ip);
                }
                if (fingerprintTrusted) {
                    registerFingerprintSighting(fingerprint, ip);
                }
            }
        }
        int score;
        long blockedUntil;
        String action = "WARN";
        boolean newBlock = false;
        boolean singleHitBlock = false;

        synchronized (state) {
            long now = System.currentTimeMillis();
            long elapsedSinceSeen = now - state.lastSeen;
            if (elapsedSinceSeen > 6 * 3600_000L) {
                state.score = 0;
                state.blockCount = 0;
            } else if (scoreDecayWindowMs > 0 && elapsedSinceSeen > scoreDecayWindowMs) {
                // IronWall v1.25.0: 超出衰减窗口未再攻击，记分折半——误触不累积，持续攻击仍快速升级
                state.score = Math.max(0, state.score / 2);
            } else if (TYPE_CRAWLER.equals(type) && crawlerDecayWindowMs > 0
                    && elapsedSinceSeen > crawlerDecayWindowMs) {
                // IronWall v1.26.0: 爬虫类命中 5 分钟未再触发的快速衰减，避免测试客户端累积到封禁线
                state.score = Math.max(0, state.score - Math.max(1, state.score / 2));
            }
            state.lastSeen = now;
            int scoreBeforeHit = state.score;
            // IronWall v1.7: 路径异常类低分载荷 30 秒内重复命中不重复加分（防误报面刷分消耗封禁名额）；
            // 真实攻击类型（SQL/XSS/穿越/命令/SSRF）保持每击 +5 的升级语义
            String signature = type + "|" + payload;
            if ((TYPE_SUSPICIOUS_PATH.equals(type) || TYPE_CRAWLER.equals(type) || TYPE_PROTOCOL.equals(type))
                    && signature.equals(state.lastSignature)
                    && now - state.lastSignatureTime < 30_000L) {
                delta = 0;
            } else {
                state.lastSignature = signature;
                state.lastSignatureTime = now;
            }
            state.score += delta;
            score = state.score;
            // IronWall v1.24.0: 单发即封识别——此前无预警累积、一击越过封禁阈值。
            // 此类封禁误伤真实用户的风险最高：仅站内封禁 + 人机验证二次确认，暂缓服务器层全端口联动。
            singleHitBlock = scoreBeforeHit < (warnScore > 0 ? warnScore : 10) && score >= effectiveBlockScore;
            // IronWall v1.26.0: 仅真实扫描工具进入扫描者画像；爬虫单独衰减，避免正常 API 集成方被标为 SCANNER
            if (TYPE_TOOL.equals(type)) {
                state.toolSeen = true;
            }
            if (state.score >= effectiveSevereScore) {
                // IronWall v1.42.0: 移动/家宽运营商出口封禁时长熔断（不出 24h 级连坐）
                long severeMs = effectiveSevereHours * 3600_000L;
                if (isMobileCarrierIp(ip)) {
                    severeMs = Math.min(severeMs, Math.max(10, mobileCarrierMaxBlockMinutes) * 60_000L);
                    mobileFuseBlockCapHits.incrementAndGet();
                }
                state.blockedUntil = now + severeMs;
                state.blockCount++;
                action = "BLOCKED";
                newBlock = true;
                maybeBlockSegment(ip, state);
            } else if (state.score >= effectiveBlockScore && state.blockedUntil <= now) {
                // IronWall v1.8: 封禁时长设 10 分钟硬下限（外部配置误设为 3 分钟也不得低于此），
                // 并按再犯次数升级：首次>=10分钟，第二次>=30分钟，第三次起直接按严重级别 24 小时封禁
                int nextBlockCount = state.blockCount + 1;
                long blockMinutesEffective;
                if (nextBlockCount >= 3) {
                    blockMinutesEffective = effectiveSevereHours * 60L;
                } else if (nextBlockCount >= 2) {
                    blockMinutesEffective = Math.max(effectiveBlockMinutes, 30L);
                } else {
                    blockMinutesEffective = Math.max(effectiveBlockMinutes, 10L);
                }
                // IronWall v1.42.0: 运营商出口封禁时长封顶（默认 30 分钟）
                if (isMobileCarrierIp(ip)) {
                    blockMinutesEffective = Math.min(blockMinutesEffective,
                            Math.max(10, mobileCarrierMaxBlockMinutes));
                    mobileFuseBlockCapHits.incrementAndGet();
                }
                state.blockedUntil = now + blockMinutesEffective * 60_000L;
                state.blockCount = nextBlockCount;
                action = "BLOCKED";
                newBlock = true;
                maybeBlockSegment(ip, state);
            }
            if (state.blockedUntil > now) {
                action = "BLOCKED";
            }
            blockedUntil = state.blockedUntil;
        }

        persistLog(ip, type, payload, path, userAgent, method, score, action);
        if (newBlock && fail2banBridgeEnabled && shouldBridgeOnBlock(type, singleHitBlock)) {
            F2B_LOG.info("IRONWALL-BLOCK ip={} category={} score={} action=BLOCKED", ip, type, score);
        }
        if (newBlock) {
            persistSyncEvent(ip, "BLOCKED", blockedUntil);
            notifyAlert(type, ip, "IP 已封禁（score=" + score + "，blockCount=" + state.blockCount + "）");
        }
        // IronWall v1.28.16: 真实攻击触发封禁瞬间锁定设备身份，换代理 IP 无效；
        // 登录态（delta=0）与噪声类型永不锁定，4G/5G 共用出口 IP 的其他设备不受影响。
        if ("BLOCKED".equals(action) && isRealAttackType(type)) {
            if (deviceId != null) {
                jailIdentity(deviceId, ip, "攻击触发IP封禁锁定设备");
            }
            if (fingerprintTrusted) {
                jailIdentity(fingerprint, ip, "攻击触发IP封禁锁定指纹", hashUserAgent(userAgent));
            }
        }
        return new AttackRecord(ip, type, payload, score, state.blockCount, blockedUntil, action);
    }

    /**
     * IronWall v1.17: 重复再犯达到阈值后升级为 IP 段封禁（IPv4 /24），
     * 对换 IP 继续攻击的顽固攻击者形成整段威慑。私网/回环/链路本地地址
     * 与可信会话永不触发，避免误伤 NAT 出口与内网基础设施。
     */
    private void maybeBlockSegment(String ip, IpState state) {
        if (!segmentBlockEnabled || state.blockCount < Math.max(2, segmentRepeatCount)) {
            return;
        }
        String segment = segmentOf(ip);
        if (segment == null || isPrivateOrReserved(ip)) {
            return;
        }
        // IronWall v1.42.0: 移动/家宽运营商出口绝不整段封禁（防 NAT/CGNAT 连坐）
        if (isMobileCarrierIp(ip)) {
            log.info("[IronWall] segment block skipped for carrier egress ip={}", ip);
            mobileFuseSegmentSkips.incrementAndGet();
            return;
        }
        long now = System.currentTimeMillis();
        int effectiveHours = segmentBlockHours > 0 ? segmentBlockHours : 48;
        SegmentState seg = segmentStates.compute(segment, (k, old) -> {
            if (old == null || old.blockedUntil <= now) {
                return new SegmentState(k, now + effectiveHours * 3600_000L, 1);
            }
            old.blockedUntil = Math.max(old.blockedUntil, now + effectiveHours * 3600_000L);
            old.blockCount++;
            return old;
        });
        log.warn("[IronWall] segment blocked: segment={} until={} count={} offender={}",
                segment, seg.blockedUntil, seg.blockCount, ip);
        persistLog(ip, TYPE_SEGMENT, "IP段封禁升级: " + segment, "/", "system", "SYSTEM",
                state.score, "SEGMENT_BLOCKED");
        notifyAlert(TYPE_SEGMENT, ip, "IP段封禁升级: " + segment);
    }

    private String segmentOf(String ip) {
        if (ip == null) return null;
        int slash = ip.indexOf('/');
        String host = slash >= 0 ? ip.substring(0, slash) : ip;
        if (host.contains(":")) return null;
        int lastDot = host.lastIndexOf('.');
        if (lastDot <= 0) return null;
        return host.substring(0, lastDot) + ".0/24";
    }

    private boolean isPrivateOrReserved(String ip) {
        if (ip == null) return true;
        String host = ip.contains("/") ? ip.substring(0, ip.indexOf('/')) : ip;
        if (host.startsWith("10.") || host.startsWith("127.") || host.startsWith("0.")
                || host.startsWith("169.254.") || host.startsWith("100.64.")) return true;
        if (host.startsWith("192.168.")) return true;
        if (host.startsWith("172.")) {
            try {
                int second = Integer.parseInt(host.split("\\.")[1]);
                if (second >= 16 && second <= 31) return true;
            } catch (Exception ignored) { }
        }
        return false;
    }

    private void persistLog(String ip, String type, String payload, String path, String userAgent, String method,
                            int score, String action) {
        try {
            AttackLog entry = new AttackLog();
            entry.setIp(ip);
            entry.setAttackType(type);
            entry.setPath(path != null && path.length() > 500 ? path.substring(0, 500) : path);
            entry.setPayload(payload != null && payload.length() > MAX_PAYLOAD_LOG_LENGTH
                    ? payload.substring(0, MAX_PAYLOAD_LOG_LENGTH) : payload);
            entry.setUserAgent(userAgent != null && userAgent.length() > 500 ? userAgent.substring(0, 500) : userAgent);
            entry.setMethod(method);
            entry.setScore(score);
            entry.setAction(action);
            entry.setCreatedAt(LocalDateTime.now());
            attackLogRepository.save(entry);
        } catch (Exception e) {
            log.warn("attack log persist failed (table may not exist yet): {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.28.1: 周期性清理过期引擎状态，防止公网扫描流量导致 IP 状态表无限增长。
     * 挑战令牌：过期即删
     * 网段封禁：封禁期结束即删
     * IP 状态：无记分、未封禁且 24 小时无活动的条目回收
     */
    @Scheduled(fixedDelay = 1_800_000L, initialDelay = 600_000L)
    public void sweepStaleStates() {
        long now = System.currentTimeMillis();
        challenges.entrySet().removeIf(e -> e.getValue().expiresAt <= now);
        segmentStates.entrySet().removeIf(e -> {
            SegmentState s = e.getValue();
            return s.blockedUntil > 0 && s.blockedUntil < now;
        });
        ipStates.entrySet().removeIf(e -> {
            IpState s = e.getValue();
            synchronized (s) {
                return s.blockedUntil < now && s.score <= 0 && now - s.lastSeen > 24 * 3600_000L;
            }
        });
        // IronWall v1.28.15: 过期协同指纹回收，防止内存无限增长
        long campaignWindowMs = campaignWindowMinutes > 0 ? campaignWindowMinutes * 60_000L : 600_000L;
        campaignHits.entrySet().removeIf(e -> now - e.getValue().firstSeen > campaignWindowMs * 2);
        // IronWall v1.28.16: 过期身份锁与指纹证据回收
        identityJails.entrySet().removeIf(e -> e.getValue().blockedUntil <= now);
        long fingerprintWindowMs = fingerprintWindowMinutes > 0 ? fingerprintWindowMinutes * 60_000L : 86_400_000L;
        fingerprintHits.entrySet().removeIf(e -> now - e.getValue().firstSeen > fingerprintWindowMs * 2);
        long deviceWindowMs = deviceWindowMinutes > 0 ? deviceWindowMinutes * 60_000L : 86_400_000L;
        deviceHits.entrySet().removeIf(e -> now - e.getValue().firstSeen > deviceWindowMs * 2);
        long churnWindowMs = fingerprintChurnWindowMinutes > 0 ? fingerprintChurnWindowMinutes * 60_000L : 3_600_000L;
        deviceFpChurn.entrySet().removeIf(e -> now - e.getValue().firstSeen > churnWindowMs * 2);
        // IronWall v1.30.0: 过期攻击族窗口回收
        long familyWindowMs = familyWindowMinutes > 0 ? familyWindowMinutes * 60_000L : 1_800_000L;
        attackFamilyHits.entrySet().removeIf(e -> now - e.getValue().firstSeen > familyWindowMs * 2);
        // IronWall v1.31.0: 过期 TLS 指纹证据回收
        long tlsWindowMs = tlsProfileWindowMinutes > 0 ? tlsProfileWindowMinutes * 60_000L : 86_400_000L;
        tlsSightings.entrySet().removeIf(e -> now - e.getValue().firstSeen > tlsWindowMs * 2);
        // IronWall v1.32.0: 过期攻击模板窗口回收
        long templateWindowMs = templateWindowMinutes > 0 ? templateWindowMinutes * 60_000L : 600_000L;
        templateHits.entrySet().removeIf(e -> now - e.getValue().firstSeen > templateWindowMs * 2);
        // IronWall v1.33.0: 相似模板桶随模板窗口回收
        similarTemplateHits.entrySet().removeIf(e -> now - e.getValue().firstSeen > templateWindowMs * 2);
    }
    public long countRecentAttacks(LocalDateTime since) {
        try {
            return attackLogRepository.countByCreatedAtAfter(since);
        } catch (Exception e) {
            return 0L;
        }
    }
}
