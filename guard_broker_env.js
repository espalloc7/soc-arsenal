const express = require("express");
const cors    = require("cors");
const dotenv  = require("dotenv");
const zlib    = require("zlib");
const { URL: NodeURL } = require("url");

dotenv.config();

// Decompress first file from a single-entry ZIP (DEFLATE or stored) — no external deps
function unzipFirstFile(buf) {
  return new Promise((resolve, reject) => {
    if (buf.readUInt32LE(0) !== 0x04034b50) { reject(new Error("Not a ZIP")); return; }
    const method   = buf.readUInt16LE(8);
    const fnLen    = buf.readUInt16LE(26);
    const exLen    = buf.readUInt16LE(28);
    const dataStart = 30 + fnLen + exLen;
    const compSize  = buf.readUInt32LE(18);
    const data      = buf.slice(dataStart, dataStart + compSize);
    if (method === 0) { resolve(data.toString("utf8")); return; }
    zlib.inflateRaw(data, (err, out) => err ? reject(err) : resolve(out.toString("utf8")));
  });
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT                = Number(process.env.PORT || 8787);
const VT_API_KEY          = process.env.VT_API_KEY          || "";
const ABUSEIPDB_API_KEY   = process.env.ABUSEIPDB_API_KEY   || "";
const IPINFO_API_KEY      = process.env.IPINFO_API_KEY      || "";   // ipinfo.io – 50k/ay ücretsiz, key opsiyonel
const OTX_API_KEY         = process.env.OTX_API_KEY         || "";   // otx.alienvault.com – free
const URLHAUS_API_KEY     = process.env.URLHAUS_API_KEY     || "";   // urlhaus.abuse.ch – free (register required)

// Shodan InternetDB, MalwareBazaar → API key gerektirmez
// URLhaus → artık Auth-Key header gerekiyor (urlhaus.abuse.ch → Register)

const FETCH_TIMEOUT_MS = 12000;
const CACHE_TTL_MS     = 60 * 60 * 1000;
const cache            = new Map();

// ─── Helpers ──────────────────────────────────────────────────────────────────

function nowIso() { return new Date().toISOString(); }

function normalizeType(type) {
  const t = String(type || "").trim().toLowerCase();
  if (t === "ipaddress" || t === "ip")                                    return "ip";
  if (t === "domainname" || t === "domain")                               return "domain";
  if (t === "url")                                                        return "url";
  if (t === "filesha256" || t === "filesha1" || t === "filemd5" || t === "hash") return "hash";
  return "unknown";
}

function cacheKey(type, value) {
  return `${type}::${String(value || "").trim().toLowerCase()}`;
}

function withTimeout(ms = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, done: () => clearTimeout(timer) };
}

async function safeFetchJson(url, options = {}) {
  const { signal, done } = withTimeout();
  try {
    const res  = await fetch(url, { ...options, signal });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { ok: res.ok, status: res.status, json, text };
  } catch (error) {
    return { ok: false, status: 0, json: null, text: "",
             error: String(error && error.message ? error.message : error) };
  } finally {
    done();
  }
}

function readCache(type, value) {
  const key  = cacheKey(type, value);
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() > item.expiresAt) { cache.delete(key); return null; }
  return item.data;
}

function writeCache(type, value, data) {
  cache.set(cacheKey(type, value), { data, expiresAt: Date.now() + CACHE_TTL_MS });
}

// ─── Provider summaries ────────────────────────────────────────────────────────

function summarizeProviders(providers) {
  const parts = [];
  if (providers.virustotal?.summary)    parts.push(`VT: ${providers.virustotal.summary}`);
  if (providers.abuseipdb?.summary)     parts.push(`AbuseIPDB: ${providers.abuseipdb.summary}`);
  if (providers.ipinfo?.summary)        parts.push(`IPInfo: ${providers.ipinfo.summary}`);
  if (providers.otx?.summary)           parts.push(`OTX: ${providers.otx.summary}`);
  if (providers.shodandb?.summary)      parts.push(`ShodanDB: ${providers.shodandb.summary}`);
  if (providers.malwarebazaar?.summary) parts.push(`MalwareBazaar: ${providers.malwarebazaar.summary}`);
  if (providers.urlhaus?.summary)       parts.push(`URLhaus: ${providers.urlhaus.summary}`);
  return parts.join(" | ");
}

// ─── Reputation index ─────────────────────────────────────────────────────────

// Well-known public DNS resolvers — static, no fetch needed
const TRUSTED_DNS_IPS = new Set([
  // Cloudflare
  "1.1.1.1","1.0.0.1",
  // Google
  "8.8.8.8","8.8.4.4",
  // Quad9
  "9.9.9.9","149.112.112.112",
  // OpenDNS / Cisco Umbrella
  "208.67.222.222","208.67.220.220","208.67.222.123","208.67.220.123",
  // AdGuard
  "94.140.14.14","94.140.15.15",
  // CleanBrowsing
  "185.228.168.168","185.228.169.168","185.228.168.9","185.228.169.9",
  // Yandex
  "77.88.8.8","77.88.8.1",
  // Alternate DNS
  "76.76.2.0","76.76.19.19","76.76.2.11",
  // NextDNS
  "45.90.28.0","45.90.30.0",
  // Level3 / CenturyLink
  "4.2.2.1","4.2.2.2","4.2.2.3","4.2.2.4","4.2.2.5","4.2.2.6",
  // Comodo SecureDNS
  "8.26.56.26","8.20.247.20",
  // Neustar UltraDNS
  "64.6.64.6","64.6.65.6",
  // SafeDNS
  "195.46.39.39","195.46.39.40",
  // DNS.WATCH
  "84.200.69.80","84.200.70.40",
]);

// Minimal IPv4-only CIDR check (no deps)
function ipv4InCidr(ipStr, cidr) {
  try {
    const [net, prefix] = cidr.split("/");
    const bits = prefix !== undefined ? parseInt(prefix, 10) : 32;
    const mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
    const toInt = s => s.split(".").reduce((a, o) => ((a << 8) | parseInt(o, 10)) >>> 0, 0);
    return (toInt(ipStr) & mask) === (toInt(net) & mask);
  } catch { return false; }
}

let CLOUD_CIDRS   = [];       // [string] IPv4 CIDR strings from major providers
let TRANCO_DOMAINS = new Set(); // top-100k FQDNs
let repIdxLastFetched = 0;
const REP_IDX_TTL = 24 * 60 * 60 * 1000;

async function loadCloudCidrs() {
  const cidrs = [];
  await Promise.allSettled([
    // Cloudflare
    safeFetchJson("https://www.cloudflare.com/ips-v4").then(r => {
      if (r.text) r.text.trim().split(/\r?\n/).forEach(l => { if (l.trim()) cidrs.push(l.trim()); });
    }),
    // Google
    safeFetchJson("https://www.gstatic.com/ipranges/goog.json").then(r => {
      (r.json?.prefixes || []).forEach(p => { if (p.ipv4Prefix) cidrs.push(p.ipv4Prefix); });
    }),
    // AWS (all services — CloudFront, S3, EC2, etc.)
    safeFetchJson("https://ip-ranges.amazonaws.com/ip-ranges.json").then(r => {
      (r.json?.prefixes || []).forEach(p => { if (p.ip_prefix) cidrs.push(p.ip_prefix); });
    }),
    // Major internet companies via BGP View ASN prefix lookup (free, no auth)
    // AS8075=Microsoft, AS13414=Twitter/X, AS32934=Meta, AS20940=Akamai, AS14907=Wikimedia
    ...["8075","13414","32934","20940","14907"].map(asn =>
      safeFetchJson(`https://api.bgpview.io/asn/${asn}/prefixes`, {
        headers: { "User-Agent": "guard-broker/1.0" },
      }).then(r => {
        (r.json?.data?.ipv4_prefixes || []).forEach(p => { if (p.prefix) cidrs.push(p.prefix); });
      }).catch(() => {})
    ),
    // Fastly
    safeFetchJson("https://api.fastly.com/public-ip-list").then(r => {
      (r.json?.addresses || []).forEach(c => cidrs.push(c));
    }),
    // GitHub
    safeFetchJson("https://api.github.com/meta", {
      headers: { "User-Agent": "guard-broker/1.0" },
    }).then(r => {
      if (!r.json) return;
      ["web","api","git","hooks","pages","packages","actions"].forEach(k => {
        (r.json[k] || []).filter(c => /^\d/.test(c) && !c.includes(":")).forEach(c => cidrs.push(c));
      });
    }),
  ]);
  return cidrs;
}

async function loadTrancoDomains() {
  const set = new Set();
  try {
    const { signal, done } = withTimeout(60000);
    const res = await fetch("https://tranco-list.eu/top-1m.csv.zip", { signal });
    done();
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const csv = await unzipFirstFile(buf);
    let count = 0;
    for (const line of csv.split("\n")) {
      if (count >= 100000) break;
      const domain = line.split(",")[1]?.trim().toLowerCase();
      if (domain) { set.add(domain); count++; }
    }
  } catch (e) {
    console.warn("[reputation] Tranco load failed:", e.message);
  }
  return set;
}

async function refreshReputationIndex(force = false) {
  const now = Date.now();
  if (!force && now - repIdxLastFetched < REP_IDX_TTL) return;
  repIdxLastFetched = now;
  console.log("[reputation] Loading cloud CIDRs + Tranco top-100k…");
  const [cidrs, domains] = await Promise.all([loadCloudCidrs(), loadTrancoDomains()]);
  CLOUD_CIDRS    = cidrs;
  TRANCO_DOMAINS = domains;
  console.log(`[reputation] ${cidrs.length} CIDRs | ${domains.size} Tranco domains`);
}

// Fire and forget on startup — first requests run without it, cache kicks in within ~10 s
refreshReputationIndex(true).catch(e => console.warn("[reputation] Startup load error:", e.message));

function ipInCloudRanges(ip) {
  return CLOUD_CIDRS.some(cidr => ipv4InCidr(ip, cidr));
}

function getRootDomain(hostname) {
  const p = hostname.toLowerCase().split(".");
  return p.length > 2 ? p.slice(-2).join(".") : hostname.toLowerCase();
}

function domainInTranco(value) {
  const v = value.toLowerCase().replace(/^www\./, "");
  return TRANCO_DOMAINS.has(v) || TRANCO_DOMAINS.has(getRootDomain(v));
}

function hostnameFromValue(type, value) {
  if (type === "url") {
    try { return new NodeURL(value).hostname; } catch { return value; }
  }
  return value;
}

// ─── Decision logic ────────────────────────────────────────────────────────────

// Reputation-only safeguard.
// We do NOT surface malicious signals here — analysts are assumed to be acting on
// legitimate CTI (otherwise the IOC wouldn't be in front of them). The guard fires
// ONLY when the analyst is about to block a well-known, high-reputation indicator
// (google.com, 1.1.1.1, cloudflare.com, etc.) so a misclick doesn't take down infra.
// Everything else returns "unknown" silently — no warning, no friction.
function decideGuard(type, value, providers) {
  const vt     = providers.virustotal || {};
  const abuse  = providers.abuseipdb  || {};
  const ipinfo = providers.ipinfo     || {};
  const sdb    = providers.shodandb   || {};

  const vtMalicious  = vt.maliciousScore  || 0;
  const vtSuspicious = vt.suspiciousScore || 0;
  const vtHarmless   = vt.harmlessScore   || 0;

  let score = 0;
  const signals = [];

  // ipinfo.io ASN — known major infrastructure operator
  if (ipinfo.trusted === true) {
    score += 10; signals.push(`Trusted ASN AS${ipinfo.asn} (${ipinfo.orgName})`);
  }

  // VirusTotal harmless consensus — only when there are zero malicious/suspicious votes
  if (vtMalicious === 0 && vtSuspicious === 0) {
    if      (vtHarmless >= 63) { score += 5; signals.push(`VT harmless=${vtHarmless}`); }
    else if (vtHarmless >= 30) { score += 3; signals.push(`VT harmless=${vtHarmless}`); }
    else if (vtHarmless >= 10) { score += 1; signals.push(`VT harmless=${vtHarmless}`); }
  }

  // AbuseIPDB whitelist flag
  if (abuse.isWhitelisted === true) { score += 5; signals.push("AbuseIPDB whitelisted"); }

  // Shodan InternetDB benign infrastructure tags
  const benignTags = ["cdn", "cloud", "cloudflare", "google", "microsoft", "amazon", "akamai", "fastly"];
  const shodanMatch = (sdb.tags || []).filter(t =>
    benignTags.includes(String(t).toLowerCase())
  );
  if (shodanMatch.length) { score += 3; signals.push(`Shodan tag=${shodanMatch[0]}`); }

  // Reputation index signals (loaded from external sources at startup, refreshed daily)
  if (type === "ip") {
    if (TRUSTED_DNS_IPS.has(value)) {
      score += 8; signals.push("trusted public DNS");
    } else if (ipInCloudRanges(value)) {
      score += 8; signals.push("cloud infra IP range");
    }
  }

  if (type === "domain" || type === "url") {
    const hostname = hostnameFromValue(type, value);
    if (domainInTranco(hostname)) {
      score += 5; signals.push("Tranco top-100k");
    }
  }

  const REPUTATION_THRESHOLD = 5;

  if (score >= REPUTATION_THRESHOLD) {
    return {
      status: "trusted_infrastructure",
      reputation_score: score,
      summary: `High-reputation indicator (score ${score}). Likely legitimate infrastructure - confirm before blocking. Signals: ${signals.join(", ")}.`,
      warn_before_block: true,
    };
  }

  return {
    status: "unknown",
    reputation_score: score,
    summary: "No high-reputation signals detected.",
    warn_before_block: false,
  };
}

// ─── Provider: VirusTotal ──────────────────────────────────────────────────────

async function queryVirusTotal(type, value) {
  if (!VT_API_KEY) return { status: "disabled", summary: "API key missing" };

  let url = "";
  const encoded = encodeURIComponent(value);

  if      (type === "ip")     url = `https://www.virustotal.com/api/v3/ip_addresses/${encoded}`;
  else if (type === "domain") url = `https://www.virustotal.com/api/v3/domains/${encoded}`;
  else if (type === "url") {
    const urlId = Buffer.from(value).toString("base64url");
    url = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  }
  else if (type === "hash")   url = `https://www.virustotal.com/api/v3/files/${encoded}`;
  else return { status: "unsupported", summary: "Type not supported" };

  const res = await safeFetchJson(url, {
    headers: { "x-apikey": VT_API_KEY, accept: "application/json" },
  });

  if (!res.ok || !res.json?.data?.attributes) {
    return { status: "error", summary: `Lookup failed${res.status ? ` (${res.status})` : ""}` };
  }

  const stats          = res.json.data.attributes.last_analysis_stats || {};
  const maliciousScore  = Number(stats.malicious  || 0);
  const suspiciousScore = Number(stats.suspicious || 0);
  const harmlessScore   = Number(stats.harmless   || 0);
  const undetectedScore = Number(stats.undetected || 0);

  return {
    status: "ok",
    maliciousScore, suspiciousScore, harmlessScore, undetectedScore,
    summary: `malicious=${maliciousScore}, suspicious=${suspiciousScore}, harmless=${harmlessScore}, undetected=${undetectedScore}`,
    link: res.json.data.links?.self || "",
  };
}

// ─── Provider: AbuseIPDB ──────────────────────────────────────────────────────

async function queryAbuseIPDB(type, value) {
  if (type !== "ip")        return { status: "unsupported", summary: "Only IP is supported" };
  if (!ABUSEIPDB_API_KEY)   return { status: "disabled",   summary: "API key missing" };

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose=true`;
  const res = await safeFetchJson(url, {
    headers: { Key: ABUSEIPDB_API_KEY, Accept: "application/json" },
  });

  if (!res.ok || !res.json?.data) {
    return { status: "error", summary: `Lookup failed${res.status ? ` (${res.status})` : ""}` };
  }

  const data                 = res.json.data;
  const abuseConfidenceScore = Number(data.abuseConfidenceScore || 0);
  const totalReports         = Number(data.totalReports         || 0);
  const usageType            = data.usageType   || "";
  const isWhitelisted        = Boolean(data.isWhitelisted);

  return {
    status: "ok",
    abuseConfidenceScore, totalReports, usageType, isWhitelisted,
    summary: `confidence=${abuseConfidenceScore}, reports=${totalReports}${usageType ? `, usage=${usageType}` : ""}${isWhitelisted ? ", whitelisted=true" : ""}`,
  };
}

// ─── Provider: GreyNoise ──────────────────────────────────────────────────────

// Trusted ASNs — major internet infrastructure operators
const TRUSTED_ASNS = new Set([
  "15169","396982","19527",  // Google / Google Cloud
  "13335","209242",          // Cloudflare
  "8075","8068",             // Microsoft / Azure
  "16509","14618",           // Amazon AWS
  "32934",                   // Meta / Facebook
  "13414",                   // Twitter / X
  "20940","16625","36183",   // Akamai
  "54113",                   // Fastly
  "36459",                   // GitHub
  "14907",                   // Wikimedia
  "22822","15133",           // Limelight / Edgecast
  "60068",                   // Datacamp (AdGuard hosted here)
  "2635",                    // Automattic / WordPress.com
  "24940",                   // Hetzner
  "34010",                   // Twilio
  "22616",                   // Salesforce
  "46606",                   // Unified Layer / Bluehost
]);

async function queryIPInfo(type, value) {
  if (type !== "ip") return { status: "unsupported", summary: "Only IP is supported" };

  const qs  = IPINFO_API_KEY ? `?token=${IPINFO_API_KEY}` : "";
  const url = `https://ipinfo.io/${encodeURIComponent(value)}/json${qs}`;
  const res = await safeFetchJson(url, { headers: { Accept: "application/json" } });

  if (!res.ok || !res.json) {
    return { status: "error", summary: `Lookup failed${res.status ? ` (${res.status})` : ""}` };
  }

  const org     = res.json.org      || "";  // "AS13335 Cloudflare, Inc."
  const host    = res.json.hostname || "";
  const country = res.json.country  || "";
  const asnMatch = org.match(/^AS(\d+)\s*(.*)/);
  const asn     = asnMatch ? asnMatch[1] : "";
  const orgName = asnMatch ? asnMatch[2] : org;
  const trusted = Boolean(asn && TRUSTED_ASNS.has(asn));

  return {
    status: "ok", asn, orgName, trusted, country,
    summary: `AS${asn || "?"} ${orgName}${host ? `, host=${host}` : ""}${trusted ? " [TRUSTED]" : ""}`,
  };
}

// ─── Provider: AlienVault OTX ─────────────────────────────────────────────────
// Ücretsiz kayıt: https://otx.alienvault.com → .env'e OTX_API_KEY ekle

async function queryOTX(type, value) {
  if (!OTX_API_KEY) return { status: "disabled", summary: "API key missing (otx.alienvault.com)" };

  let indicatorType;
  if      (type === "ip")     indicatorType = "IPv4";
  else if (type === "domain") indicatorType = "domain";
  else if (type === "url")    indicatorType = "url";
  else if (type === "hash") {
    const len = value.replace(/\s/g, "").length;
    if      (len === 32) indicatorType = "FileHash-MD5";
    else if (len === 40) indicatorType = "FileHash-SHA1";
    else if (len === 64) indicatorType = "FileHash-SHA256";
    else return { status: "unsupported", summary: "Unknown hash length" };
  } else return { status: "unsupported", summary: "Type not supported" };

  const url = `https://otx.alienvault.com/api/v1/indicators/${indicatorType}/${encodeURIComponent(value)}/general`;
  const res = await safeFetchJson(url, {
    headers: { "X-OTX-API-KEY": OTX_API_KEY, Accept: "application/json" },
  });

  if (!res.ok || !res.json) {
    return { status: "error", summary: `Lookup failed${res.status ? ` (${res.status})` : ""}` };
  }

  const pulseCount  = Number(res.json.pulse_info?.count   || 0);
  const reputation  = Number(res.json.reputation          || 0);
  const malwareList = (res.json.malware_families || []).map(m => m.display_name || m.id).slice(0, 3);

  return {
    status: "ok", pulseCount, reputation,
    malwareFamilies: malwareList,
    summary: `pulses=${pulseCount}, reputation=${reputation}${malwareList.length ? `, malware=${malwareList.join(",")}` : ""}`,
  };
}

// ─── Provider: Shodan InternetDB ──────────────────────────────────────────────
// API key gerektirmez. https://internetdb.shodan.io

async function queryShodanInternetDB(type, value) {
  if (type !== "ip") return { status: "unsupported", summary: "Only IP is supported" };

  const url = `https://internetdb.shodan.io/${encodeURIComponent(value)}`;
  const res = await safeFetchJson(url);

  if (res.status === 404) {
    return { status: "ok", known: false, summary: "No data in Shodan InternetDB" };
  }
  if (!res.ok || !res.json) {
    return { status: "error", summary: `Lookup failed${res.status ? ` (${res.status})` : ""}` };
  }

  const vulns     = res.json.vulns     || [];
  const tags      = res.json.tags      || [];
  const ports     = res.json.ports     || [];
  const hostnames = res.json.hostnames || [];

  return {
    status: "ok", known: true, vulns, tags, ports, hostnames,
    summary: `ports=${ports.length}${vulns.length ? `, CVEs=${vulns.slice(0,3).join(",")}` : ""}${tags.length ? `, tags=${tags.join(",")}` : ""}${hostnames.length ? `, host=${hostnames[0]}` : ""}`,
  };
}

// ─── Provider: MalwareBazaar ──────────────────────────────────────────────────
// API key gerektirmez. https://bazaar.abuse.ch

async function queryMalwareBazaar(type, value) {
  if (type !== "hash") return { status: "unsupported", summary: "Only file hashes" };

  const body = `query=get_info&hash=${encodeURIComponent(value)}`;
  const res  = await safeFetchJson("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok || !res.json) {
    return { status: "error", summary: `Lookup failed${res.status ? ` (${res.status})` : ""}` };
  }

  if (res.json.query_status === "hash_not_found") {
    return { status: "ok", found: false, summary: "Not found in MalwareBazaar" };
  }

  const data        = (res.json.data || [])[0] || {};
  const signature   = data.signature  || "";
  const fileType    = data.file_type  || "";
  const tags        = data.tags       || [];
  const deliveryMethod = data.delivery_method || "";

  return {
    status: "ok", found: true,
    signature, fileType, tags, deliveryMethod,
    summary: `FOUND${signature ? `: ${signature}` : ""}${fileType ? `, type=${fileType}` : ""}${tags.length ? `, tags=${tags.slice(0,3).join(",")}` : ""}`,
  };
}

// ─── Provider: URLhaus ────────────────────────────────────────────────────────
// API key gerektirmez. https://urlhaus.abuse.ch

async function queryURLhaus(type, value) {
  if (!["url", "domain", "ip"].includes(type)) {
    return { status: "unsupported", summary: "Only URL / domain / IP" };
  }
  if (!URLHAUS_API_KEY) {
    return { status: "disabled", summary: "API key missing (urlhaus.abuse.ch → Register)" };
  }

  let endpoint, body;

  if (type === "url") {
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/";
    body     = `url=${encodeURIComponent(value)}`;
  } else {
    // domain or ip → host lookup
    endpoint = "https://urlhaus-api.abuse.ch/v1/host/";
    body     = `host=${encodeURIComponent(value)}`;
  }

  const res = await safeFetchJson(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Auth-Key": URLHAUS_API_KEY,
    },
    body,
  });

  if (!res.ok || !res.json) {
    return { status: "error", summary: `Lookup failed${res.status ? ` (${res.status})` : ""}` };
  }

  const qs = res.json.query_status || "";

  if (qs === "unknown_auth_key") {
    return { status: "error", summary: "Invalid URLhaus API key" };
  }

  if (qs === "no_results" || qs === "invalid_url" || qs === "invalid_host") {
    return { status: "ok", found: false, summary: "Not found in URLhaus" };
  }

  const urlCount  = type === "url" ? 1 : Number(res.json.urls_count || 0);
  const threat    = res.json.threat    || res.json.url_status || "";
  const tags      = res.json.tags      || [];

  return {
    status: "ok", found: true,
    urlCount, threat, tags,
    summary: `FOUND in URLhaus${threat ? `: ${threat}` : ""}${urlCount > 1 ? `, urls=${urlCount}` : ""}${tags.length ? `, tags=${tags.slice(0,3).join(",")}` : ""}`,
  };
}

// ─── Enrichment ───────────────────────────────────────────────────────────────

async function enrichOne(indicator) {
  const value = String((indicator && indicator.value) || "").trim();
  const type  = normalizeType(indicator && indicator.type);

  if (!value || type === "unknown") {
    return {
      value, type,
      guard_status: "unknown",
      summary: "Unsupported or invalid indicator.",
      warn_before_block: false,
      provider_hits: [],
      providers: {},
      checked_at: nowIso(),
    };
  }

  const cached = readCache(type, value);
  if (cached) return Object.assign({}, cached, { cache: "hit" });

  const providers = {};
  const tasks     = [];

  // VirusTotal – all types
  tasks.push(queryVirusTotal(type, value).then(r => { providers.virustotal = r; }));

  // IP-only providers
  if (type === "ip") {
    tasks.push(queryAbuseIPDB(type, value).then(r        => { providers.abuseipdb = r; }));
    tasks.push(queryIPInfo(type, value).then(r            => { providers.ipinfo    = r; }));
    tasks.push(queryShodanInternetDB(type, value).then(r => { providers.shodandb  = r; }));
  }

  // Hash-only providers
  if (type === "hash") {
    tasks.push(queryMalwareBazaar(type, value).then(r => { providers.malwarebazaar = r; }));
  }

  // URL + domain + IP → URLhaus
  if (["url", "domain", "ip"].includes(type)) {
    tasks.push(queryURLhaus(type, value).then(r => { providers.urlhaus = r; }));
  }

  // OTX – all types (if key present)
  if (OTX_API_KEY) {
    tasks.push(queryOTX(type, value).then(r => { providers.otx = r; }));
  }

  await Promise.allSettled(tasks);

  const decision = decideGuard(type, value, providers);
  const result = {
    value, type,
    guard_status:     decision.status,
    reputation_score: decision.reputation_score,
    summary:          decision.summary,
    provider_summary: summarizeProviders(providers),
    warn_before_block: decision.warn_before_block,
    provider_hits: Object.entries(providers)
      .filter(([, v]) => v && v.status === "ok")
      .map(([k]) => k),
    providers,
    checked_at:        nowIso(),
    stale_after_minutes: 60,
  };

  writeCache(type, value, result);
  return result;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "guard-broker",
    time: nowIso(),
    providers: {
      virustotal:    Boolean(VT_API_KEY),
      abuseipdb:     Boolean(ABUSEIPDB_API_KEY),
      ipinfo:        true,   // key-free up to 50k/mo; set IPINFO_API_KEY for higher limits
      otx:           Boolean(OTX_API_KEY),
      shodandb:      true,                    // key-free
      malwarebazaar: true,                    // key-free
      urlhaus:       Boolean(URLHAUS_API_KEY),
    },
  });
});

app.post("/api/guard/check", async (req, res) => {
  try {
    const indicators = Array.isArray(req.body?.indicators) ? req.body.indicators : [];
    if (!indicators.length) {
      return res.status(400).json({ error: "indicators array is required" });
    }
    const results = await Promise.all(indicators.map(enrichOne));
    res.json({ results });
  } catch (error) {
    res.status(500).json({
      error: "Internal error",
      detail: String(error?.message ?? error),
    });
  }
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`[guard-broker] listening on http://127.0.0.1:${PORT}`);
  console.log(`[guard-broker] providers: VT=${Boolean(VT_API_KEY)} | AbuseIPDB=${Boolean(ABUSEIPDB_API_KEY)} | IPInfo=true | OTX=${Boolean(OTX_API_KEY)} | ShodanDB=true | MalwareBazaar=true | URLhaus=${Boolean(URLHAUS_API_KEY)}`);
});
