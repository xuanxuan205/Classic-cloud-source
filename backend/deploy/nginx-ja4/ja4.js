// IronWall v1.38.0: nginx njs JA4 形会话指纹（边缘层）.
// 说明：nginx 不解析 ClientHello 扩展列表，无法产出 100% 标准 JA4；
// 本脚本用 njs 可取字段（协议版本 / SNI / ALPN / 协商密码套件）计算 JA4 形状指纹，
// 后端 TlsProfileResolver 已优先消费 X-TLS-JA4（见）。
// 用途：跨 IP 攻击证据聚合与告警，绝不单独用于封禁（防止误封同版本浏览器群体）。
'use strict';

const crypto = require('crypto');

// 常见密码套件 -> JA4 密码字节（OpenSSL 名称到 TLS 套件号）
const CIPHER_JA4 = {
    'TLS_AES_128_GCM_SHA256': '1301',
    'TLS_AES_256_GCM_SHA384': '1302',
    'TLS_CHACHA20_POLY1305_SHA256': '1303',
    'TLS_AES_128_CCM_SHA256': '1304',
    'TLS_AES_128_CCM_8_SHA256': '1305',
    'ECDHE-ECDSA-AES128-GCM-SHA256': 'c02b',
    'ECDHE-RSA-AES128-GCM-SHA256': 'c02f',
    'ECDHE-ECDSA-AES256-GCM-SHA384': 'c02c',
    'ECDHE-RSA-AES256-GCM-SHA384': 'c030',
    'ECDHE-ECDSA-CHACHA20-POLY1305': 'cca9',
    'ECDHE-RSA-CHACHA20-POLY1305': 'cca8',
    'ECDHE-RSA-AES128-SHA': 'c013',
    'ECDHE-RSA-AES256-SHA': 'c014',
    'AES128-GCM-SHA256': '1301',
    'AES256-GCM-SHA384': '1302'
};

// ALPN -> JA4 两字符段
const ALPN_JA4 = {
    'h2': 'h2',
    'http/1.1': 'h1',
    'http/1.0': 'h0'
};

function sha12(input) {
    return crypto.createHash('sha256').update(input, 'utf8').digest('hex').substring(0, 12);
}

function normVersion(raw) {
    const m = String(raw || '').match(/\d\.(\d)/);
    if (!m) return '00';
    const minor = parseInt(m[1], 10);
    return minor >= 10 ? String(minor) : '0' + minor;
}

function ja4(r) {
    const proto = normVersion(r.variables.ssl_protocol);
    const sni = r.variables.ssl_server_name || r.variables.host || '';
    const alpn = ALPN_JA4[r.variables.ssl_alpn_protocol] || '00';
    const cipher = CIPHER_JA4[r.variables.ssl_cipher] || '0000';
    // 密码套件数量 / 扩展数量 nginx 不可得，按 JA4 形状置 0000（后端仅做形状校验）
    const a = 't' + proto + (sni ? 'd' : 'i') + '0000' + alpn;
    const b = sha12(a);
    const d = sha12(b + ',' + cipher);
    return a + '_' + b + '_' + d;
}

export default { ja4 };
