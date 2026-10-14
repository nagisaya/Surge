/**
 * Surge / Stash IP Security Check Script
 *
 * 功能概述：
 * - 檢測並顯示本地/入口/出口 IP 資訊
 * - 評估 IP 風險等級和類型
 * - 顯示地理位置和電信業者資訊
 * - 支援網路變化自動檢測和通知
 *
 * 資料來源：
 * ① 本地 IP: bilibili API (DIRECT)
 * ② 出口 IP: Surge 使用 Cloudflare trace → ip.sb；Stash 與官方卡片一樣使用 IPPure，IPv4 缺失時回落 ipify
 * ③ 入口 IP: Surge /v1/requests/recent → remoteAddress(Proxy)
 * ④ 代理策略: Surge /v1/requests/recent
 * ⑤ 風險評分: IPQS (需 Key) → ProxyCheck → IPPure → Scamalytics；risk_api 指定優先源
 *    Surge 按出口 IP 快取 24 小時；Stash 預設 IPPure 優先，失敗按 ProxyCheck → Scamalytics 回退，不使用需金鑰的來源
 * ⑥ IP 類型: IPPure API → ProxyCheck type 欄位回退（重複使用風險評分的請求；與風險評分同樣按出口 IP 24 小時快取）
 * ⑦ 地理: 本地百度 → bilibili → ip.sb；出口 ipapi-zh → ipapi → ipinfo → MaxMind（Stash 不含 MaxMind）；參數指定優先選項
 * ⑧ 出口電信業者: 兩端優先 ipinfo.io；失敗保留成功地區源或本輪出口探測的電信業者
 * ⑨ DNS 解析器: edns.ip-api.com；Surge 按解析器地區作提示，未驗證是否屬於本地 ISP
 * ⑩ 反向 DNS: ipinfo.io hostname 欄位
 * ⑪ 流量統計: Surge /v1/traffic API
 *
 * 參數說明：
 * - TYPE: 設為 EVENT 表示網路變化觸發（自動判斷，無需手動設定）
 * - ipqs_key: IPQualityScore API Key（僅 Surge，可選，優先選項或回退到 IPQS 時使用）
 * - risk_api: 優先風險源，ipqs / proxycheck / ippure / scamalytics；Stash 預設 ippure 且不支援 ipqs；優先選項失敗後按預設順序嘗試剩餘來源
 * - local_geoapi: 本地地區優先選項，預設 baidu；baidu / bilibili / ipsb 指定優先源，失敗按百度 → bilibili → ip.sb 嘗試剩餘來源
 * - remote_geoapi: 出口地區優先選項（入口仍按選定源查詢），預設 ipapi-zh → ipapi → ipinfo → maxmind；優先使用所選來源且不重複，MaxMind 無憑證跳過；Stash 不支援 MaxMind，可選 ippure。ipapi-zh=ip-api.com(中文, http 明文)，ipinfo=ipinfo.io，ipapi=ip-api.com(英文)，maxmind=GeoLite2(英文)，maxmind-zh=GeoLite2(中文優先)
 * - maxmind_key: MaxMind GeoLite 憑證，格式 account_id:license_key（僅 Surge，MaxMind 優先選項或回退時使用，未填跳過，免費註冊 1000 次/天）
 * - mask_ip: IP 遮蔽，0=關閉，1=部分遮蔽，2=全部隱藏 [IP 已隱藏]，預設 0
 * - tw_flag: 台灣地區旗幟，cn(預設)=🇨🇳，tw=🇹🇼
 * - event_delay: 網路變化後延遲檢測（秒），預設 2 秒
 * - notify: 網路變化時是否推播通知，true(預設)=推播，false=不推播；Stash 獨立定時任務比較 IP，首次僅記錄
 * - panel_interval: 面板 update-interval（秒），預設 600；改了 [Panel] 的 update-interval 需同步此參數，
 *   否則遮蔽點選切換的自動重新整理判定會失準
 *
 * 設定範例：
 * [Panel]
 * ip-security-panel = script-name=ip-security-panel,update-interval=600
 *
 * [Script]
 * # 手動觸發（面板）- ipqs_key 可選，不填自動回落
 * ip-security-panel = type=generic,timeout=15,script-path=ip-security.js,argument=ipqs_key=YOUR_API_KEY&panel_interval=600
 *
 * # 網路變化自動觸發
 * ip-security-event = type=event,event-name=network-changed,timeout=15,script-path=ip-security.js,argument=TYPE=EVENT&ipqs_key=YOUR_API_KEY&event_delay=2&notify=true
 *
 * @author HotKids&Claude
 * Stash：ip-security-panel.stoverride 提供首頁聚合與三張折疊卡片，600 秒重新整理；與 Surge 共用此檔案。
 * - summary 首頁 IP 資訊卡；outbound 出口、local 本地、risk 純淨度維持獨立折疊檢測。
 * - Stash 預設風險源 IPPure、本地百度、出口地區 ipapi-zh；可用 risk_api / local_geoapi / remote_geoapi 改選。
 *   Stash 僅用免金鑰來源（不含 IPQS/MaxMind）；remote_geoapi=ippure 是額外可選源，其他地區源按指定 IP 查詢。
 *   本地與出口均按上述順序回退，參數可指定優先選項；出口全部地區源失敗後才保留本輪探測地區，電信業者優先 ipinfo。
 *   地區與電信業者每輪查詢，不重複使用歷史欄位；風險資料快取保持獨立。
 *   兩端共用六級風險等級與顏色，首頁補充 DNS 解析器、rDNS、顯式指定的策略名。
 *   DNS 地區只作展示，不據此判斷洩漏；遮蔽時同時隱藏可能包含 IP 的 rDNS。
 *   腳本 notify 預設 true；配套卡片顯式關閉通知，僅 monitor 定時任務開啟。
 * - 覆寫 argument 內的 tile 用於選擇卡片；其餘選項已預設，不需要匯入參數介面。
 * - proxy: 可手動指定 URL 編碼的節點/策略組名；留空遵循當前分流。
 * - mode: home / collapsed（獨立卡片預設）；折疊模式不覆寫 Stash 長按節點時指定的出口。
 * - iOS 折疊卡片按 $environment.system 自動使用單行標題：Ⓓ / 🅟 + IP，純淨度只顯示百分比。
 * - mask_ip: Stash 固定按參數顯示，不通過重新整理時間猜測點選切換。
 * - Stash 不呼叫 Surge 專用 API，不顯示入口 IP/流量統計，不訂閱 network-changed 事件。
 *   task=monitor 獨立定時通知 IP 變化；卡片不寫通知基線，避免長按測試節點時誤報。
 *   IP 變化後補查本地/出口地區、電信業者及 IPPure 風險，再傳送通知；
 *   與 Surge 一樣，首行匯總本地/出口 IP，正文依次為風險控管、出口、本地；各詳情行保留 IP。
 *   只展示本輪有效 IP 對應的資料，不依賴 Surge 的入口或策略查詢介面。
 * - log=shared: Stash 各卡片與通知記錄按任務暫存；task=logs 獨立收集到一個腳本記錄。
 *
 * @version 6.4.15
 * @date 2026-10-01
 */

// ==================== 全域設定 ====================
const isStash = (typeof $environment !== "undefined" &&
  (!!$environment["stash-version"] || !!$environment["stash-build"])) ||
  (typeof $script !== "undefined" && $script.type === "tile");
const stashSystem = typeof $environment !== "undefined" ? String($environment.system || "").trim().toLowerCase() : "";
const isStashiOS = isStash && (stashSystem === "ios" || stashSystem === "ipados");
const hasTimers = typeof setTimeout === "function";
// 圖示統一由覆寫提供；更新檢測結果時保留卡片 Logo。
const stashTiles = {
  summary: { title: "IP 資訊卡", color: "#9E9E9E" },
  risk: { title: "IP 純淨度", color: "#88A788" },
  dns: { title: "DNS 解析器", color: "#7357A6" },
  outbound: { title: "出口 IP", marker: "🅟", color: "#1565C0" },
  local: { title: "本地 IP", marker: "Ⓓ", color: "#00796B" }
};
const CONFIG = {
  timeout: isStash ? 20000 : 10000, // Surge 看門狗須小於 sgmodule 的 timeout=15；Stash 相容無 JS 定時器的執行環境
  riskCacheTTL: 86400, // 風險評分快取有效期（秒）：出口 IP 未變化時，此時間長度內重複使用快取，
                       // 避免面板自動重新整理（update-interval，預設 600s）反覆消耗 IPQS 等按次計費額度
  storeKeys: {
    lastEvent: "lastNetworkInfoEvent",
    lastPolicy: "lastProxyPolicy",
    riskCache: "riskScoreCache",
    ipTypeCache: "ipTypeCache",
    maskToggle: "ipMaskToggle",
    lastRun: "ipLastRunTime"
  },
  urls: {
    localIP: "https://api.bilibili.com/x/web-interface/zone",
    baiduGeo: (ip) => `https://opendata.baidu.com/api.php?query=${ip}&co=&resource_id=6006&oe=utf8`,
    maxmindGeo: (ip) => `https://geolite.info/geoip/v2.1/city/${ip}`,
    // Cloudflare 官方端點，憑證含 IP SAN，可直連（不經 DNS）；失敗回落 ip.sb
    outboundTrace: "https://1.1.1.1/cdn-cgi/trace",
    outboundTrace6: "https://[2606:4700:4700::1111]/cdn-cgi/trace",
    outboundIP: "https://api-ipv4.ip.sb/geoip",
    outboundIPv6: "https://api-ipv6.ip.sb/geoip",
    stashIPv4: "https://api.ipify.org?format=json",
    stashIPv6: "https://api6.ipify.org?format=json",
    ipType: "https://my.ippure.com/v1/info",
    ipTypeCard: "https://my.ippure.com/v1/card",
    ipSbGeo: (ip) => `https://api.ip.sb/geoip/${ip}`,
    ipInfo: (ip) => `https://ipinfo.io/${ip}/json`,
    ipApi: (ip, lang) => `http://ip-api.com/json/${ip}?lang=${lang}&fields=status,country,countryCode,regionName,city,isp,org`,
    ipqs: (key, ip) => `https://ipqualityscore.com/api/json/ip/${key}/${ip}?strictness=1`,
    proxyCheck: (ip) => `https://proxycheck.io/v2/${ip}?risk=1&vpn=1`,
    scamalytics: (ip) => `https://scamalytics.com/ip/${ip}`,
    dnsLeakEdns: (id) => `http://${id}.edns.ip-api.com/json`
  },
  ipv6Timeout: 3000,
  stashIPv4Timeout: 5000, // IPPure 失敗後的 IPv4 備用請求預算，仍受總時間限制約束
  policyRetryDelay: 500,
  riskLevels: [
    { max: 15, label: "極度純淨", color: "#0D6E3D" },
    { max: 25, label: "純淨",     color: "#2E9F5E" },
    { max: 40, label: "一般",     color: "#8BC34A" },
    { max: 50, label: "微風險",   color: "#FFC107" },
    { max: 70, label: "一般風險", color: "#FF9800" },
    { max: 100, label: "極度風險", color: "#F44336" }
  ]
};

// 每個卡片/通知任務使用獨立佇列，收集器僅記錄已輸出 ID，不清空生產者的佇列。
class IPLog {
  static PREFIX = "stash_ip_security_log_v1:";
  static SCOPES = ["summary", "outbound", "local", "risk", "notify"];
  static RUN_ID = Date.now().toString(36) + ":" + Math.random().toString(36).slice(2);
  static sequence = 0;

  static native(value) {
    try { console.log(value); } catch {}
  }

  static text(value) {
    if (typeof value === "string") return value;
    if (value instanceof Error) return value.message || String(value);
    try { return JSON.stringify(value) ?? String(value); } catch { return String(value); }
  }

  static readQueue(scope) {
    const raw = $persistentStore.read(IPLog.PREFIX + scope);
    if (!raw) return [];
    const entries = JSON.parse(raw);
    if (!Array.isArray(entries)) return [];
    return entries.filter(entry => entry && typeof entry.id === "string"
      && Number.isFinite(entry.time) && Math.abs(entry.time) <= 8640000000000000
      && typeof entry.text === "string").slice(-60);
  }

  static log(...values) {
    let text;
    try { text = values.map(value => IPLog.text(value)).join(" "); }
    catch { text = "[ip-security] 記錄內容無法格式化"; }
    if (!isStash || args.log !== "shared" || args.task === "logs") {
      IPLog.native(text);
      return;
    }
    try {
      const scope = args.task === "monitor" ? "notify"
        : IPLog.SCOPES.includes(args.tile) ? args.tile : "summary";
      const time = Date.now();
      const entry = {
        id: `${time}:${IPLog.RUN_ID}:${String(IPLog.sequence++).padStart(6, "0")}`,
        time,
        text: text.slice(0, 2000)
      };
      const entries = IPLog.readQueue(scope);
      entries.push(entry);
      if ($persistentStore.write(JSON.stringify(entries.slice(-60)), IPLog.PREFIX + scope) === false) {
        throw new Error("記錄儲存寫入失敗");
      }
    } catch {
      IPLog.native(text);
    }
  }

  static collect() {
    const pending = [];
    const queues = [];
    for (const scope of IPLog.SCOPES) {
      try {
        const entries = IPLog.readQueue(scope);
        const ackKey = IPLog.PREFIX + "ack:" + scope;
        const previous = JSON.parse($persistentStore.read(ackKey) || "[]");
        const seen = new Set(Array.isArray(previous) ? previous : []);
        for (const entry of entries) {
          if (!seen.has(entry.id)) pending.push({ ...entry, scope });
        }
        const ids = entries.map(entry => entry.id);
        if (ids.some(id => !seen.has(id)) || seen.size !== ids.length) queues.push({ ackKey, ids });
      } catch {
        IPLog.native(`[ip-security][${scope}] 無法讀取記錄佇列`);
      }
    }
    pending.sort((a, b) => a.time - b.time || a.id.localeCompare(b.id));
    for (const entry of pending) {
      IPLog.native(`[${new Date(entry.time).toISOString()}][${entry.scope}] ${entry.text}`);
    }
    for (const queue of queues) {
      try {
        if ($persistentStore.write(JSON.stringify(queue.ids), queue.ackKey) === false) {
          throw new Error("記錄確認寫入失敗");
        }
      } catch {
        IPLog.native("[ip-security] 無法儲存記錄確認狀態，下次可能重複輸出");
      }
    }
  }
}

// ==================== 參數解析 ====================
function parseArguments() {
  let arg = {};
  const decode = value => { try { return decodeURIComponent(value); } catch (_) { return value; } };

  if (typeof $argument !== "undefined") {
    // 不輸出 $argument 原文：其中可能含 ipqs_key 等敏感憑證
    arg = Object.fromEntries($argument.split("&").map(i => {
      const idx = i.indexOf("=");
      return idx === -1 ? [i.trim(), ""] : [i.slice(0, idx).trim(), decode(i.slice(idx + 1)).trim()];
    }));
  }

  const isPanel = typeof $input !== "undefined" && $input.purpose === "panel";
  const isRequest = typeof $request !== "undefined";
  if (!isStash && !isPanel && !isRequest) {
    arg.TYPE = "EVENT";
  }

  function clean(val) {
    if (!val) return "";
    const v = String(val).trim();
    return (v === "" || v.toLowerCase() === "null") ? "" : v;
  }

  if (!isStash) IPLog.log("參數解析: risk_api=" + JSON.stringify(arg.risk_api) + " ipqs_key=" + (arg.ipqs_key ? "已設定" : "未設定"));

  // notify 參數：預設 true，僅當明確設為 "false" 時關閉通知
  const notifyVal = clean(arg.notify).toLowerCase();
  const notify = notifyVal !== "false";

  return {
    isEvent: !isStash && arg.TYPE === "EVENT",
    proxy: isStash && clean(arg.mode) !== "collapsed" ? clean(arg.proxy) : "",
    mode: clean(arg.mode) === "collapsed" ? "collapsed" : "home",
    tile: clean(arg.tile) || "outbound",
    task: clean(arg.task),
    log: clean(arg.log),
    ipqsKey: isStash ? "" : clean(arg.ipqs_key),
    riskApi: isStash && clean(arg.risk_api).toLowerCase() === "ipqs" ? "ippure" :
      clean(arg.risk_api).toLowerCase() || (isStash ? "ippure" : ""),
    maxmindKey: isStash ? "" : clean(arg.maxmind_key),
    localGeoApi: clean(arg.local_geoapi) || "baidu",
    remoteGeoApi: clean(arg.remote_geoapi) || "ipapi-zh",
    maskIP: arg.mask_ip === "2" ? 2 : (arg.mask_ip === "1" || arg.mask_ip === "true") ? 1 : 0,
    twFlag: clean(arg.tw_flag) || (isStash ? "tw" : "cn"),
    eventDelay: parseFloat(arg.event_delay) || 2,
    notify: notify,
    panelInterval: parseInt(clean(arg.panel_interval), 10) || 600
  };
}

const args = parseArguments();

if (!(isStash && args.task === "logs")) IPLog.log("觸發類型: " + (args.isEvent ? "EVENT" : "MANUAL") + ", risk_api: " + (args.riskApi || "fallback") + ", 本地: " + args.localGeoApi + ", 通知: " + args.notify);

// ==================== 全域狀態控制 ====================
let finished = false;
let watchdog = null;
const requestDeadline = Date.now() + CONFIG.timeout - 250;

function done(o) {
  if (finished) return;
  finished = true;
  if (watchdog !== null && typeof clearTimeout === "function") clearTimeout(watchdog);
  if (isStash && (args.task === "monitor" || args.task === "logs")) {
    $done({});
  } else if (isStash) {
    $done({
      title: o.title || stashTiles[args.tile]?.title || "IP Security",
      content: o.content || "檢測失敗",
      backgroundColor: o.backgroundColor || o["icon-color"] || "#9E9E9E",
      url: o.url || "https://ippure.com"
    });
  } else {
    $done(o);
  }
}

if (hasTimers && !(isStash && args.task === "logs")) {
  watchdog = setTimeout(() => {
    done({ title: "檢測逾時", content: "API 請求逾時", icon: "leaf", "icon-color": "#9E9E9E" });
  }, CONFIG.timeout);
}

// ==================== HTTP 工具 ====================
function logHTTPFailure(url, status, error) {
  // 只記錄站點和錯誤類別；完整 URL 可能含 IP 或 API Key。
  const host = String(url).match(/^https?:\/\/([^/?#]+)/)?.[1] || "API";
  const detail = String(error || "");
  const reason = error ? (/script wait deadline/i.test(detail) ? "腳本等待期限已到" :
    /timeout|timed out/i.test(detail) ? "請求逾時" :
    /dns|resolve|lookup/i.test(detail) ? "DNS 解析失敗" :
    /invalid JSON/i.test(detail) ? "JSON 回應無效" :
    /tls|ssl|certificate/i.test(detail) ? "TLS 連線失敗" : "網路請求失敗") :
    (status ? "HTTP " + status : "無有效回應");
  IPLog.log("[IP HTTP] " + host + "：" + reason);
}

function httpRaw(url, policy, headers, deadline = requestDeadline) {
  const remaining = Math.min(deadline, requestDeadline) - Date.now();
  if (finished || remaining < 100) return Promise.resolve(null);
  return new Promise(resolve => {
    let req = { url };
    const nativeIPPure = isStash && url === CONFIG.urls.ipType;
    let settled = false, timer = null;
    const complete = (error, response, data) => {
      if (settled) return;
      settled = true;
      if (timer !== null && typeof clearTimeout === "function") clearTimeout(timer);
      const status = Number(response?.status || response?.statusCode);
      if (error || !(status >= 200 && status < 300)) logHTTPFailure(url, status, error);
      resolve(!error && status >= 200 && status < 300 ? (data || null) : null);
    };
    if (headers) req.headers = { ...headers };
    if (isStash) {
      // IPPure 與官方腳本一樣使用原生 HTTP 預設值；其他請求的 timeout 單位為秒。
      if (!nativeIPPure) req.timeout = Math.min(5, remaining / 1000);
      const selected = policy || args.proxy;
      if (selected) req.headers = { ...req.headers, "X-Stash-Selected-Proxy": encodeURIComponent(selected) };
      // 不用新增的 5 秒腳本截止截斷 IPPure；保留總期限，避免原生請求不回呼時停滯。
      if (hasTimers) timer = setTimeout(() => complete("script wait deadline", null, null),
        nativeIPPure ? remaining : Math.min(5000, remaining));
      if (nativeIPPure && !req.headers) req = url;
    } else {
      if (policy) req.policy = policy;
      // 分級地理查詢需在單次請求逾時後繼續回退；總期限仍由看門狗控制。
      if (deadline !== requestDeadline) {
        req.timeout = remaining / 1000;
        if (hasTimers) timer = setTimeout(() => complete("script wait deadline", null, null), remaining);
      }
    }
    try {
      $httpClient.get(req, complete);
    } catch (error) { complete(error, null, null); }
  });
}

async function httpJSON(url, policy, headers, deadline) {
  const raw = await httpRaw(url, policy, headers, deadline);
  try { return raw ? JSON.parse(raw) : null; }
  catch (_) { logHTTPFailure(url, 0, "invalid JSON"); return null; }
}

function wait(ms) {
  return hasTimers ? new Promise(r => setTimeout(r, ms)) : Promise.resolve();
}

function surgeAPI(method, path) {
  if (isStash || typeof $httpAPI !== "function") return Promise.resolve(null);
  return new Promise(r => {
    $httpAPI(method, path, null, res => r(res));
  });
}

// 單次執行內去重：Stash 出口、評分和類型與官方卡片一樣取自同一份 IPPure 資料。
// 不跨重新整理快取此回應，避免節點切換後沿用另一個出口。
let _ippureInfoP = null, _ippureCardP = null;
function getIPPureInfo() { return _ippureInfoP || (_ippureInfoP = httpJSON(CONFIG.urls.ipType)); }
function getIPPureCard() { return _ippureCardP || (_ippureCardP = httpRaw(CONFIG.urls.ipTypeCard)); }
// 同輪摘要的出口與風險回退共用一次 IPv4 探測，不跨執行儲存。
let _stashOutbound4P = null;

// ProxyCheck 請求去重：風險評分和 IP 類型回退共享同一個請求
let _proxyCheckP = null;
function getProxyCheck(ip) { return _proxyCheckP || (_proxyCheckP = httpJSON(CONFIG.urls.proxyCheck(ip))); }

// ==================== 資料處理工具 ====================
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  cc = cc.toUpperCase();
  if (cc === "TW" && args.twFlag !== "tw") cc = "CN";
  const b = 0x1f1e6;
  return String.fromCodePoint(b + cc.charCodeAt(0) - 65, b + cc.charCodeAt(1) - 65);
}

function riskText(score) {
  if (score === null || score === undefined || !Number.isFinite(Number(score))) {
    return { label: "檢測失敗", color: "#9E9E9E" };
  }
  const level = CONFIG.riskLevels.find(l => score <= l.max) || CONFIG.riskLevels.at(-1);
  return { label: level.label, color: level.color };
}

function formatRisk(info) {
  if (info.score === null || info.score === undefined) return "未知（檢測失敗）";
  return info.score + "% " + riskText(info.score).label + " (" + info.source + ")";
}

function maskIP(ip, mode) {
  if (!ip || !mode) return ip;
  if (mode === 2) return "[IP 已隱藏]";
  if (ip.includes(":")) {
    if (ip.includes("::")) {
      // :: 壓縮記法（如 2001:db8::1）：真實分段數不固定，無法按未壓縮地址逐段遮蔽，
      // 僅顯示首尾各一段，中間（含被壓縮的隱藏段）統一用 ** 代替
      const [left = "", right = ""] = ip.split("::");
      const leftGroups = left ? left.split(":") : [];
      const rightGroups = right ? right.split(":") : [];
      const first = leftGroups[0] || rightGroups[0];
      const last = rightGroups.at(-1) || leftGroups.at(-1);
      if (!first || !last) return ip;
      return first === last ? "::" + first : first + "::**:" + last;
    }
    const parts = ip.split(":");
    if (parts.length <= 2) return ip;
    return parts[0] + ":" + parts.slice(1, -1).map(() => "**").join(":") + ":" + parts.at(-1);
  }
  const parts = ip.split(".");
  if (parts.length !== 4) return ip;
  return parts[0] + ".***.***." + parts[3];
}

function formatGeo(countryCode, ...parts) {
  const unique = parts.filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);
  return flag(countryCode) + " " + unique.join(", ");
}

function normalizeIpSb(data) {
  if (!data || !data.country_code) return null;
  return {
    country_code: data.country_code,
    country_name: data.country,
    city: data.city,
    region: data.region,
    org: data.organization
  };
}

function normalizeIpInfo(data) {
  if (!data || !data.country) return null;
  return {
    country_code: data.country,
    country_name: data.country,
    city: data.city,
    region: data.region,
    org: data.org ? data.org.replace(/^AS\d+\s*/, "") : ""
  };
}

/**
 * 將 ip-api.com 回傳欄位正規化為內部格式
 * ip-api.com: { status:"success", country, countryCode, regionName, city, isp, org }
 */
function normalizeIpApi(data) {
  if (!data || data.status !== "success") return null;
  return {
    country_code: data.countryCode,
    country_name: data.country,
    city: data.city,
    region: data.regionName,
    org: data.isp || data.org || ""
  };
}

/**
 * 將百度 opendata 回傳正規化為內部格式
 * opendata 6006: { status:"0", data:[{ location:"廣東省深圳市 移動" }] }
 * location 首段為地理（整體放 country_name 供中文顯示），其餘為電信業者；
 * country_code 無法提供，由呼叫方回填（本地預設 CN）
 */
function normalizeOpendata(data) {
  const loc = data?.data?.[0]?.location;
  if (!loc) return null;
  const parts = String(loc).trim().split(/\s+/);
  return {
    country_code: null,
    country_name: parts[0] || "",
    city: "",
    region: "",
    org: parts.slice(1).join(" ")
  };
}

// Basic Auth 用 base64（Surge JSC 無內建 btoa，憑證為 ASCII）
function b64(s) {
  if (typeof btoa !== "undefined") return btoa(s);
  const c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < s.length; i += 3) {
    const c1 = s.charCodeAt(i), c2 = s.charCodeAt(i + 1), c3 = s.charCodeAt(i + 2);
    out += c[c1 >> 2] + c[((c1 & 3) << 4) | (isNaN(c2) ? 0 : c2 >> 4)]
      + (isNaN(c2) ? "=" : c[((c2 & 15) << 2) | (isNaN(c3) ? 0 : c3 >> 6)])
      + (isNaN(c3) ? "=" : c[c3 & 63]);
  }
  return out;
}

/**
 * 將 MaxMind GeoLite2 city 回傳正規化為內部格式
 * geolite.info/geoip/v2.1/city: { country:{iso_code,names}, city:{names}, subdivisions:[{names}] }
 * zhFirst=true 時中文名優先、缺失回落英文（maxmind-zh），否則英文（maxmind）
 */
function normalizeMaxmind(data, zhFirst) {
  if (!data || !data.country?.iso_code) return null;
  const pick = n => (zhFirst ? (n?.["zh-CN"] || n?.en) : n?.en) || "";
  return {
    country_code: data.country.iso_code,
    country_name: pick(data.country.names),
    city: pick(data.city?.names),
    region: pick(data.subdivisions?.[0]?.names),
    org: ""
  };
}

function normalizeBilibili(data) {
  const d = data?.data;
  if (!d || !d.country) return null;
  let isp = d.isp || "";
  if (/^(移[动動]|[联聯]通|[电電]信|[广廣][电電])$/.test(isp)) isp = "中国" + isp;
  return {
    country_code: null,
    country_name: d.country,
    city: d.city || "",
    region: d.province,
    org: isp
  };
}

async function getLocalGeo(local) {
  const ip = local?.data?.addr;
  if (!ip) return { info: null, source: "" };
  const defaults = ["baidu", "bilibili", "ipsb"];
  const preferred = defaults.includes(args.localGeoApi) ? args.localGeoApi : "baidu";
  const order = [preferred, ...defaults.filter(source => source !== preferred)];
  const policy = isStash ? "DIRECT" : undefined;
  // ip.sb 同時補充國家代碼；bilibili 重複使用本輪取得本地 IP 的回應。
  const sbPromise = httpJSON(CONFIG.urls.ipSbGeo(ip), policy, null, Date.now() + 5000);
  let info = null, source = "";
  for (source of order) {
    IPLog.log("本地地區：嘗試 " + source);
    info = source === "baidu" ? normalizeOpendata(await httpJSON(CONFIG.urls.baiduGeo(ip), policy, null, Date.now() + 2000))
      : source === "bilibili" ? normalizeBilibili(local) : normalizeIpSb(await sbPromise);
    if (info && [info.country_code, info.country_name, info.region, info.city].some(value => typeof value === "string" && value.trim())) break;
    info = null;
    IPLog.log("本地地區：" + source + " 無有效地區，繼續回退");
  }
  const sb = normalizeIpSb(await sbPromise);
  if (info && source !== "ipsb") {
    if (/^(移[动動]|[联聯]通|[电電]信|[广廣][电電])$/.test(info.org)) info.org = "中国" + info.org;
    info.country_code = sb?.country_code || (source === "bilibili" && info.country_name !== "中国" ? "" : "CN");
  }
  if (info) IPLog.log("本地地區：採用 " + source);
  return { info, source };
}

async function getOutboundGeo(ip, probeInfo, pureInfo) {
  const defaults = isStash ? ["ipapi-zh", "ipapi", "ipinfo"] : ["ipapi-zh", "ipapi", "ipinfo", "maxmind"];
  const allowed = [...defaults, ...(isStash ? ["ippure"] : ["maxmind-zh"])];
  const preferred = allowed.includes(args.remoteGeoApi) ? args.remoteGeoApi : "ipapi-zh";
  // MaxMind 中英文使用同一個介面，指定中文時替換預設英文級，不重複查詢。
  const order = [preferred, ...defaults.filter(source => source !== preferred &&
    !(source === "maxmind" && preferred === "maxmind-zh"))];
  // ipinfo 還用於電信業者/rDNS，預先發起並在地區回退時重複使用，不改變地區選用順序。
  const orgPromise = httpJSON(CONFIG.urls.ipInfo(ip), undefined, null, Date.now() + 5000);
  let info = null;
  for (const source of order) {
    if (source.startsWith("maxmind") && !args.maxmindKey) {
      IPLog.log("出口地區：跳過 " + source + "（未填寫 maxmind_key）");
      continue;
    }
    IPLog.log("出口地區：嘗試 " + source);
    if (source === "ippure") info = pureInfo;
    else if (source === "ipinfo") info = normalizeIpInfo(await orgPromise);
    else if (source.startsWith("maxmind")) info = normalizeMaxmind(await httpJSON(
      CONFIG.urls.maxmindGeo(ip), undefined, { Authorization: "Basic " + b64(args.maxmindKey) }, Date.now() + 2000), source === "maxmind-zh");
    else info = normalizeIpApi(await httpJSON(CONFIG.urls.ipApi(ip, source === "ipapi-zh" ? "zh-CN" : "en"),
      undefined, null, Date.now() + 2000));
    if (info && [info.country_code, info.country_name, info.region, info.city].some(value => typeof value === "string" && value.trim())) {
      IPLog.log("出口地區：採用 " + source);
      break;
    }
    info = null;
    IPLog.log("出口地區：" + source + " 無有效地區，繼續回退");
  }
  if (!info && probeInfo) {
    info = probeInfo;
    IPLog.log("出口地區：回退來源均無有效結果，保留本輪出口探測地區");
  }
  const org = await orgPromise, orgInfo = normalizeIpInfo(org);
  if (info && orgInfo?.org) info.org = orgInfo.org;
  return { info, reverseDNS: typeof org?.hostname === "string" ? org.hostname.trim() : "" };
}

function parseScamalyticsScore(html) {
  const m = html?.match(/Fraud Score[^0-9]*([0-9]{1,3})/i);
  return m ? Number(m[1]) : null;
}

// ==================== 代理策略與入口 IP 取得 ====================
/**
 * 從 Surge 最近請求中同時取得代理策略和入口 IP
 * 入口 IP 通過 remoteAddress 的 (Proxy) 後綴識別
 */
async function getPolicyAndEntrance() {
  if (isStash) return { policy: args.proxy || (args.mode === "collapsed" ? "當前檢測出口" : "按規則分流"), entranceIP: null };
  const pattern = /(api(-ipv4)?\.ip\.sb|ipinfo\.io|ip-api\.com|\b1\.1\.1\.1\b|2606:4700|opendata\.baidu\.com|geolite\.info)/i;

  async function findInRecent(limit) {
    const res = await surgeAPI("GET", "/v1/requests/recent");
    return (res?.requests || []).slice(0, limit).find(i => pattern.test(i.URL));
  }

  let hit = await findInRecent(50);
  if (!hit) {
    IPLog.log("未找到策略記錄，等待後重試 (1/2)");
    await wait(CONFIG.policyRetryDelay);
    hit = await findInRecent(50);
  }
  if (!hit) {
    IPLog.log("未找到策略記錄，等待後重試 (2/2)");
    await wait(CONFIG.policyRetryDelay * 2);
    hit = await findInRecent(100);
  }

  const validPolicy = name => typeof name === "string" && name.trim() !== "" && !/^unknown$/i.test(name.trim());
  const policy = hit?.policyName;
  // 命中請求但缺少策略名時也回退；失敗結果不能覆寫上次有效策略。
  if (!validPolicy(policy)) {
    const storedPolicy = $persistentStore.read(CONFIG.storeKeys.lastPolicy);
    const lastPolicy = validPolicy(storedPolicy) ? storedPolicy : null;
    IPLog.log(lastPolicy ? "使用上次儲存的策略: " + lastPolicy : "無法找到任何策略資訊");
    return { policy: lastPolicy || "Unknown", entranceIP: null };
  }

  $persistentStore.write(policy, CONFIG.storeKeys.lastPolicy);
  IPLog.log("找到代理策略: " + policy);

  let entranceIP = null;
  if (/\(Proxy\)/.test(hit.remoteAddress)) {
    entranceIP = hit.remoteAddress.replace(/\s*\(Proxy\)\s*/, "").replace(/:\d+$/, "");
    IPLog.log("找到入口 IP: " + entranceIP);
  }

  return { policy, entranceIP };
}

// ==================== 風險評分取得 ====================
// 優先嘗試指定源，失敗後繼續其餘源；Stash 預設 IPPure，指定其他源時重複使用此流程。
// 不填或其他值 → 四級回落（IPQS → ProxyCheck → IPPure → Scamalytics）
// Surge 快取策略：出口 IP、risk_api、是否帶 Key 均未變化，且快取未超過 riskCacheTTL
// （預設 24 小時）時直接重複使用，不再重新請求；IP 變化或快取過期才會重新查詢
async function getRiskScore(ip) {
  const api = args.riskApi;
  const hasKey = !!args.ipqsKey;

  const cached = !isStash && $persistentStore.read(CONFIG.storeKeys.riskCache);
  if (cached) {
    try {
      const c = JSON.parse(cached);
      const age = Math.floor(Date.now() / 1000) - (c.ts || 0);
      if (c.ip === ip && (c.api || "") === api && !!c.hasKey === hasKey && age < CONFIG.riskCacheTTL) {
        IPLog.log("風險評分命中快取: " + c.score + "% (" + c.source + ")，已快取 " + age + "s");
        return { score: c.score, source: c.source };
      }
    } catch (e) {}
  }

  function saveAndReturn(score, source) {
    if (!(typeof score === "number" || typeof score === "string" && score.trim())) return null;
    score = Number(score);
    if (!Number.isFinite(score) || score < 0 || score > 100) return null;
    IPLog.log("風險評分：採用 " + source);
    if (isStash) return { score, source };
    $persistentStore.write(JSON.stringify({ ip, score, source, api, hasKey, ts: Math.floor(Date.now() / 1000) }), CONFIG.storeKeys.riskCache);
    IPLog.log("風險評分已快取: " + score + "% (" + source + ")");
    return { score, source };
  }

  async function tryIPQS() {
    if (!args.ipqsKey) return null;
    const data = await httpJSON(CONFIG.urls.ipqs(args.ipqsKey, ip));
    if (data?.success && data?.fraud_score !== undefined) return saveAndReturn(data.fraud_score, "IPQS");
    IPLog.log("IPQS 失敗: " + (data ? "success=" + data.success + " message=" + (data.message || "") : "請求失敗"));
    return null;
  }

  async function tryProxyCheck() {
    const data = await getProxyCheck(ip);
    if (data?.[ip]?.risk !== undefined) return saveAndReturn(data[ip].risk, "ProxyCheck");
    IPLog.log("ProxyCheck 失敗: " + (data ? JSON.stringify(data).slice(0, 100) : "請求失敗"));
    return null;
  }

  async function tryIPPure() {
    const info = await getIPPureInfo();
    // IPPure 查詢使用者自身；不能把另一路出口的評分套到指定 IP 上。
    if (isStash && stashCacheIP(info?.ip) !== ip) return null;
    if (info?.fraudScore !== undefined) return saveAndReturn(info.fraudScore, "IPPure");
    if (isStash) return null; // card HTML 沒有可核驗的目標 IP。
    IPLog.log("IPPure /v1/info 無 fraudScore，回落到 /v1/card");
    const html = await getIPPureCard();
    if (html) {
      const m = html.match(/(\d+)\s*%\s*([极極]度[纯純][净淨]|[纯純][净淨]|一般|微[风風][险險]|一般[风風][险險]|[极極]度[风風][险險])/);
      if (m) return saveAndReturn(Number(m[1]), "IPPure");
    }
    IPLog.log("IPPure 風險評分取得失敗");
    return null;
  }

  async function tryScamalytics() {
    const html = await httpRaw(CONFIG.urls.scamalytics(ip));
    const score = parseScamalyticsScore(html);
    if (score !== null) return saveAndReturn(score, "Scamalytics");
    IPLog.log("Scamalytics 失敗: " + (html ? "解析失敗" : "請求失敗"));
    return null;
  }

  const tryMap = { ipqs: tryIPQS, proxycheck: tryProxyCheck, ippure: tryIPPure, scamalytics: tryScamalytics };
  if (api && !tryMap[api]) IPLog.log("未知 risk_api: " + api + "，按預設順序回退");

  const defaults = isStash ? ["proxycheck", "ippure", "scamalytics"] : ["ipqs", "proxycheck", "ippure", "scamalytics"];
  const order = defaults.includes(api) ? [api, ...defaults.filter(key => key !== api)] : defaults;
  for (const key of order) {
    if (key === "ipqs" && !args.ipqsKey) {
      IPLog.log("風險評分：跳過 ipqs（未填寫 ipqs_key）");
      continue;
    }
    IPLog.log("風險評分：嘗試 " + key);
    const r = await tryMap[key]();
    if (r) return r;
  }

  // 所有資料源均失敗：僅為本次展示回傳未知狀態，不寫入快取，
  // 避免一次性的臨時故障被 24h TTL 放大成長期錯誤風險控管值
  IPLog.log("風險評分：所有資料源均失敗，顯示未知（不快取）");
  return { score: null, source: "Unavailable" };
}

// ==================== IP 類型檢測（二級回落） ====================
// Surge IP 類型是資料源對當前地址的分類，可能變化；按出口 IP 最多快取 24 小時，
// 避免面板自動重新整理反覆消耗 IPPure 額度
async function getIPType(ip) {
  const cached = $persistentStore.read(CONFIG.storeKeys.ipTypeCache);
  if (cached) {
    try {
      const c = JSON.parse(cached);
      const age = Math.floor(Date.now() / 1000) - (c.ts || 0);
      if (c.ip === ip && age < CONFIG.riskCacheTTL) {
        IPLog.log("IP 類型命中快取: " + c.ipType + " | " + c.ipSrc + "，已快取 " + age + "s");
        return { ipType: c.ipType, ipSrc: c.ipSrc };
      }
    } catch (e) {}
  }

  function saveAndReturn(ipType, ipSrc) {
    $persistentStore.write(JSON.stringify({ ip, ipType, ipSrc, ts: Math.floor(Date.now() / 1000) }), CONFIG.storeKeys.ipTypeCache);
    return { ipType, ipSrc };
  }

  const info = await getIPPureInfo();
  if (info && info.isResidential !== undefined) {
    IPLog.log("IPPure /v1/info 回傳 IP 類型資料");
    return saveAndReturn(
      info.isResidential ? "住宅 IP" : "機房 IP",
      info.isBroadcast ? "廣播 IP" : "原生 IP"
    );
  }
  IPLog.log("IPPure /v1/info 未回傳 IP 類型，回落到 /v1/card");

  const html = await getIPPureCard();
  if (html) {
    const ipType = /住宅|[Rr]esidential/.test(html) ? "住宅 IP" : "機房 IP";
    const ipSrc = /[广廣]播|[Bb]roadcast|[Aa]nnounced/.test(html) ? "廣播 IP" : "原生 IP";
    IPLog.log("IPPure /v1/card 抓取結果: " + ipType + " | " + ipSrc);
    return saveAndReturn(ipType, ipSrc);
  }

  // IPPure 全部失敗後讀取 ProxyCheck type；本輪已有請求則重複使用，否則發起一次。
  const pc = await getProxyCheck(ip);
  const pcType = pc?.[ip]?.type;
  if (pcType) {
    const ipType = /residential|wireless|mobile/i.test(pcType) ? "住宅 IP" : "機房 IP";
    IPLog.log("ProxyCheck type 回退: " + pcType + " → " + ipType);
    return saveAndReturn(ipType, "未知");
  }

  IPLog.log("IPPure/ProxyCheck 所有介面均失敗");
  return { ipType: "未知", ipSrc: "未知" };
}

// ==================== DNS 洩漏檢測 ====================
async function checkDNSLeak(policy, deadline) {
  const c = "abcdefghijklmnopqrstuvwxyz0123456789";
  function randStr(len) { let s = ""; for (let i = 0; i < len; i++) s += c[Math.floor(Math.random() * c.length)]; return s; }

  // edns.ip-api.com：隨機子域觸發 DNS 查詢，伺服器端回傳解析器 IP 和地理資訊
  const ednsData = await httpJSON(CONFIG.urls.dnsLeakEdns(randStr(32)), policy, null, deadline);
  if (!ednsData?.dns) {
    IPLog.log("DNS 洩漏檢測失敗");
    return { leaked: null, resolvers: null };
  }
  const ip = ednsData.dns.ip || "";
  const geo = ednsData.dns.geo || "";
  const isChina = /China|中[国國]/i.test(geo);
  const name = (geo.includes(" - ") ? geo.split(" - ").pop().trim() : (geo || ip)).replace(/\s*communications\s+corporation/gi, "");
  const resolvers = ip ? [{ ip, name, geo, isChina }] : [];
  // 既有啟發式：解析器位於中國即作提示；未比較本地 ISP，不能證明有/無 DNS 洩漏。
  const leaked = isChina;
  IPLog.log("DNS 解析器: " + (resolvers.length ? resolvers[0].name + (isChina ? " [CN]" : "") : "無"));
  return { leaked, resolvers: resolvers.length > 0 ? resolvers : null };
}

// ==================== 流量統計 ====================
function formatBytes(bytes) {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + " " + units[i];
}

function formatDuration(seconds) {
  if (!seconds || seconds < 0) return "0s";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return h + "h " + m + "m";
  if (m > 0) return m + "m " + s + "s";
  return s + "s";
}

async function getTrafficStats() {
  if (isStash) return null;
  const data = await surgeAPI("GET", "/v1/traffic");
  if (!data) {
    IPLog.log("流量統計取得失敗");
    return null;
  }
  IPLog.log("流量統計原始資料: " + JSON.stringify(data).slice(0, 300));

  // Surge 回傳 interface 為巢狀字典 { en0: {...}, pdp_ip0: {...}, lo0: {...} }
  let network = null;
  if (data.interface && typeof data.interface === "object") {
    const keys = Object.keys(data.interface).filter(k => k !== "lo0");
    if (keys.length > 0) {
      network = data.interface[keys[0]];
      IPLog.log("使用網路介面卡: " + keys[0]);
    }
  }
  if (!network) network = data.connector || data;
  const upload = network.out ?? 0;
  const download = network.in ?? 0;
  const rawStart = data.startTime;
  const startMs = rawStart
    ? (typeof rawStart === "number" && rawStart < 1e12 ? rawStart * 1000 : new Date(rawStart).getTime())
    : null;
  const duration = startMs ? Math.floor((Date.now() - startMs) / 1000) : null;

  return { upload, download, duration };
}

// ==================== IP 取得 ====================
// Cloudflare cdn-cgi/trace 純文字回應（ip=x.x.x.x\nloc=US\n…）→ 物件
function parseTrace(text) {
  if (!text || typeof text !== "string" || !text.includes("ip=")) return null;
  const o = {};
  text.trim().split("\n").forEach(l => {
    const i = l.indexOf("=");
    if (i > 0) o[l.slice(0, i)] = l.slice(i + 1);
  });
  return o.ip ? o : null;
}

// 官方 IPPure Tile 使用的地理欄位；只用於同一次回應確認的出口。
function normalizeStashIPPure(data) {
  const text = value => typeof value === "string" ? value.trim() : "";
  const code = text(data.countryCode).toUpperCase();
  return {
    country_code: /^[A-Z]{2}$/.test(code) ? code : "",
    country_name: text(data.country), city: text(data.city), region: text(data.region),
    org: text(data.asOrganization)
  };
}

// 按 Stash 官方 IPPure 卡片：請求經當前檢測節點，IP、評分和類型來自它的回應。
// 缺少相應地址族時才用 ipify 補充 IP，不用另一站點的地址否定 IPPure 評分。
async function probeStashOutbound4() {
  const info = await getIPPureInfo();
  if (finished) return null;
  const ip = stashCacheIP(info?.ip);
  if (ip && !ip.includes(":")) return { ip };
  if (requestDeadline - Date.now() < 100) return null;
  const deadline = Math.min(requestDeadline, Date.now() + CONFIG.stashIPv4Timeout);
  IPLog.log("IPPure 未提供有效 IPv4，使用 ipify 備用探測");
  const backup = await httpJSON(CONFIG.urls.stashIPv4, null, null, deadline);
  if (finished) return null;
  const backupIP = stashCacheIP(backup?.ip);
  return backupIP && !backupIP.includes(":") ? { ip: backupIP } : null;
}

async function probeStashOutbound6() {
  const info = await getIPPureInfo();
  if (finished) return null;
  const pureIP = stashCacheIP(info?.ip);
  if (pureIP.includes(":")) return pureIP;
  const deadline = Date.now() + CONFIG.ipv6Timeout;
  const data = await httpJSON(CONFIG.urls.stashIPv6, null, null, deadline);
  if (finished) return null;
  const ip = stashCacheIP(data?.ip);
  if (ip.includes(":")) return ip;
  IPLog.log("IPv6 未探測到有效地址，僅展示 IPv4");
  return null;
}

// Surge 保持原有 Cloudflare trace → ip.sb。
async function fetchOutbound4() {
  if (isStash) {
    return _stashOutbound4P || (_stashOutbound4P = probeStashOutbound4());
  }
  const t = parseTrace(await httpRaw(CONFIG.urls.outboundTrace));
  if (t) return { ip: t.ip, raw: { country_code: t.loc, country: t.loc } };
  IPLog.log("CF trace(v4) 失敗，回落 ip.sb");
  const sb = await httpJSON(CONFIG.urls.outboundIP);
  return sb?.ip ? { ip: sb.ip, raw: sb } : null;
}

async function fetchOutbound6() {
  if (isStash) {
    return probeStashOutbound6();
  }
  const deadline = Date.now() + CONFIG.ipv6Timeout;
  const t = parseTrace(await httpRaw(CONFIG.urls.outboundTrace6, null, null, deadline));
  if (t) return t.ip;
  IPLog.log("CF trace(v6) 失敗，回落 ip.sb");
  const sb = await httpJSON(CONFIG.urls.outboundIPv6, null, null, deadline);
  return sb?.ip || null;
}

async function fetchIPs() {
  const [local, exit, exit6ip] = await Promise.all([
    httpJSON(CONFIG.urls.localIP, "DIRECT"),
    fetchOutbound4(),
    !isStash && hasTimers ? Promise.race([
      fetchOutbound6(),
      wait(CONFIG.ipv6Timeout).then(() => null)
    ]) : fetchOutbound6()
  ]);

  const hasIPv6 = exit6ip && exit6ip.includes(":");

  return {
    localIP: local?.data?.addr || null,
    outIP: exit?.ip || null,
    outIPv6: hasIPv6 ? exit6ip : null,
    localRaw: local,
    outRaw: exit?.raw || null
  };
}

// ==================== 網路變化檢測 ====================
function checkIPChange(localIP, outIP, outIPv6) {
  if (!args.isEvent) return true;

  const lastEvent = $persistentStore.read(CONFIG.storeKeys.lastEvent);
  let lastData = {};
  if (lastEvent) {
    try { lastData = JSON.parse(lastEvent); } catch (e) {}
  }

  if (localIP === lastData.localIP && outIP === lastData.outIP && outIPv6 === lastData.outIPv6) {
    IPLog.log("網路資訊未變化，跳過");
    return false;
  }

  IPLog.log("網路資訊已變化");
  $persistentStore.write(JSON.stringify({ localIP, outIP, outIPv6 }), CONFIG.storeKeys.lastEvent);
  return true;
}

// Stash 通知專用上下文：不讀取/寫入節點測試卡片的記錄。
// 各 IP 欄位獨立建立基線；失敗欄位沿用舊值，不妨礙其他有效變化。
async function runStashMonitor() {
  if (!args.notify || (typeof $script !== "undefined" && $script.type === "tile")) return done({});
  const current = await fetchIPs();
  if (finished) return;
  const key = "stash.ip-security.monitor.v2:" + encodeURIComponent(args.proxy || "routing");
  let previous = {};
  try { previous = JSON.parse($persistentStore.read(key) || "{}"); } catch (_) {}
  if (!previous || typeof previous !== "object" || Array.isArray(previous)) previous = {};
  const next = { ...previous };
  let changed = false;
  for (const field of ["outIP", "localIP", "outIPv6"]) {
    const value = current[field];
    if (!value) continue;
    if (previous[field] && previous[field] !== value) {
      changed = true;
    }
    next[field] = value;
  }
  if (changed) {
    if (typeof $notification === "undefined" || typeof $notification.post !== "function") {
      IPLog.log("當前用戶端未提供通知介面；保留基線供下次重試");
      return done({});
    }
    // 僅變化後補查詳情，沿用本輪 IP/IPPure 回應，不再探測一遍出口。
    const results = await Promise.allSettled([
      getStashLocalResult(current.localRaw),
      current.outIP ? getStashOutboundResult(false, { ip: current.outIP, raw: current.outRaw }) : null,
      current.outIP ? getStashRiskResult() : null
    ]);
    if (finished) return;
    const [local, outbound, risk] = results.map(result => result.status === "fulfilled" ? result.value : null);
    const sameRisk = risk?.ip === current.outIP ? risk : null;
    const m = ip => ip ? maskIP(ip, args.maskIP) : "查詢失敗";
    const detail = info => (info?.location ? formatGeo(info.countryCode, info.location) : "地區查詢失敗") +
      " · " + (info?.organization || "電信業者未知");
    const title = "🔄 網路已切換" + (args.proxy ? " | " + args.proxy : "");
    const subtitle = "Ⓓ " + m(current.localIP) + " 🅟 " + m(current.outIP);
    const lines = ["🅟 風險控管：" + (sameRisk?.valid ? formatRisk(sameRisk) : "未知（檢測失敗）") +
      " | 類型：" + (sameRisk?.typeText || "類型未知 · 來源未知"),
      "🅟 " + m(current.outIP) + " " + detail(outbound)];
    if (current.outIPv6) lines.push("🅟 IPv6：" + m(current.outIPv6));
    lines.push("Ⓓ " + m(current.localIP) + " " + detail(local));
    try { $notification.post(title, subtitle, lines.join("\n")); }
    catch (_) { IPLog.log("通知傳送失敗；保留基線供下次重試"); return done({}); }
  }
  if (Object.keys(next).length) {
    try { $persistentStore.write(JSON.stringify(next), key); }
    catch (_) { IPLog.log("通知記錄儲存失敗"); }
  }
  done({});
}

// IP 驗證供出口確認及風險欄位快取共用；地區與電信業者不使用歷史欄位快取。
function stashCacheIP(value) {
  if (typeof value !== "string") return "";
  const ip = value.trim().toLowerCase();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    return ip.split(".").every(n => Number(n) <= 255) ? ip : "";
  }
  // IPv6 快取鍵保留地址寫法；不同等價寫法最多造成未命中，不會串用地址。
  if (!/^[0-9a-f:]+$/.test(ip) || ip.includes(":::") ||
    (ip.startsWith(":") && !ip.startsWith("::")) ||
    (ip.endsWith(":") && !ip.endsWith("::"))) return "";
  const halves = ip.split("::"), groups = ip.split(":").filter(Boolean);
  if (halves.length > 2 || !groups.every(n => /^[0-9a-f]{1,4}$/.test(n))) return "";
  return halves.length === 2 ? (groups.length < 8 ? ip : "") :
    (groups.length === 8 && !ip.startsWith(":") && !ip.endsWith(":") ? ip : "");
}

function stashFields(values, ts = Date.now()) {
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [key, { value, ts }]));
}

function stashLastGood(kind, ip, fresh, fallback = {}) {
  const key = "stash.ip-security.last-good.v1", ttl = 86400000, now = Date.now();
  const address = stashCacheIP(ip), id = kind + ":" + address;
  const valid = (name, value) => name === "score" ?
    typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100 :
    ["isResidential", "isBroadcast"].includes(name) ? typeof value === "boolean" :
    name === "countryCode" ? typeof value === "string" && /^[A-Z]{2}$/.test(value) :
    typeof value === "string" && !!value.trim();
  const usable = (name, field) => field && Number.isFinite(field.ts) &&
    now - field.ts >= 0 && now - field.ts < ttl && valid(name, field.value);
  let entries = {};
  try {
    const stored = JSON.parse($persistentStore.read(key) || "{}");
    if (stored && typeof stored === "object" && !Array.isArray(stored)) entries = stored;
  } catch (_) {}
  const previous = address ? entries[id]?.fields || {} : {};
  const fields = {}, data = {};
  let cached = false;
  for (const name of Object.keys(fresh)) {
    let field = fresh[name];
    if (!usable(name, field)) {
      if (usable(name, previous[name])) { field = previous[name]; cached = true; }
      else field = fallback[name];
    }
    if (usable(name, field)) { fields[name] = field; data[name] = field.value; }
  }
  if (address && Object.keys(fields).length) {
    // 沿用每個欄位原始時間；失敗重新整理不延長舊資料壽命，也不覆寫其他 IP。
    const ts = Math.max(...Object.values(fields).map(field => field.ts));
    const retained = Object.entries(entries).filter(([entry, value]) => entry !== id &&
      Number.isFinite(value?.ts) && now - value.ts >= 0 && now - value.ts < ttl);
    retained.push([id, { ts, fields }]);
    retained.sort((a, b) => a[1].ts - b[1].ts);
    try { $persistentStore.write(JSON.stringify(Object.fromEntries(retained.slice(-32))), key); }
    catch (_) { IPLog.log("上次成功結果儲存失敗，繼續顯示本次結果"); }
  }
  if (cached) IPLog.log("[IP 快取] " + kind + "：重複使用同一 IP 的上次成功欄位");
  return { data, cached };
}

// ==================== 面板內容構建 ====================
function geoLabel(info) {
  // ip-api.com(zh): country_name="香港"(非 ASCII) → 顯示中文國名
  // ip-api.com(en): country_name="Hong Kong" / ipinfo.io: country_name="HK" → 顯示 country_code
  return (info?.country_name && /[^\x00-\x7F]/.test(info.country_name)) ? info.country_name : info?.country_code;
}

function buildOutboundSection(outIP, outIPv6, outInfo, maskMode, reverseDNS) {
  const lines = [];
  const m = (ip) => maskIP(ip, maskMode);

  if (outIPv6) {
    lines.push("出口 IP⁴：" + m(outIP));
    lines.push("出口 IP⁶：" + m(outIPv6));
  } else {
    lines.push("出口 IP：" + m(outIP));
  }
  lines.push("地區：" + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.region, geoLabel(outInfo)));
  lines.push("電信業者：" + (outInfo?.org || "Unknown"));
  if (reverseDNS) lines.push("rDNS：" + reverseDNS);

  return lines;
}

function buildPanelContent({ localZh, maskMode, riskInfo, riskResult, ipType, ipSrc, localIP, localInfo, entranceIP, entranceInfo, outIP, outIPv6, outInfo, dnsLeak, reverseDNS, traffic }) {
  const m = (ip) => maskIP(ip, maskMode);
  const lines = [
    "IP 風險控管值：" + formatRisk(riskInfo),
  ];

  // DNS 洩漏檢測
  if (dnsLeak) {
    if (dnsLeak.leaked === null) {
      lines.push("DNS 檢測：檢測失敗");
    } else if (dnsLeak.resolvers) {
      const names = [...new Set(dnsLeak.resolvers.map(r => r.name).filter(Boolean))];
      if (dnsLeak.leaked) {
        const leakedNames = [...new Set(dnsLeak.resolvers.filter(r => r.isChina).map(r => r.name))];
        lines.push("DNS 檢測：⚠️ 洩漏! " + leakedNames.join(", "));
      } else {
        lines.push("DNS 檢測：無洩漏 (" + names.join(" / ") + ")");
      }
    } else {
      lines.push("DNS 檢測：無洩漏");
    }
  }

  lines.push(
    "",
    "IP 類型：" + ipType + " | " + ipSrc,
    "",
    "本地 IP：" + m(localIP),
    "地區：" + formatGeo(localInfo?.country_code, localInfo?.city, localInfo?.region, localZh ? localInfo?.country_name : localInfo?.country_code),
    "電信業者：" + (localInfo?.org || "Unknown"),
  );

  if (entranceInfo) {
    lines.push(
      "",
      "入口 IP：" + m(entranceIP),
      "地區：" + formatGeo(entranceInfo?.country_code, entranceInfo?.city, entranceInfo?.region, geoLabel(entranceInfo)),
      "電信業者：" + (entranceInfo?.org || "Unknown")
    );
  }

  lines.push("", ...buildOutboundSection(outIP, outIPv6, outInfo, maskMode, reverseDNS));

  // 流量統計
  if (traffic) {
    lines.push(
      "",
      "流量統計：↑ " + formatBytes(traffic.upload) + "  ↓ " + formatBytes(traffic.download)
        + (traffic.duration ? " | ⏱ " + formatDuration(traffic.duration) : "")
    );
  }

  return lines.join("\n");
}

// ==================== 通知內容構建 ====================
function sendNetworkChangeNotification({ localZh, policy, localIP, outIP, entranceIP, localInfo, entranceInfo, outInfo, riskInfo, riskResult, ipType, ipSrc, maskMode, dnsLeak }) {
  if (!args.notify) {
    IPLog.log("通知已停用 (notify=false)，跳過推播");
    return;
  }

  const m = (ip) => maskIP(ip, maskMode);
  const policyLabel = typeof policy === "string" ? policy.trim() : "";
  const title = "🔄 網路已切換" + (policyLabel && !/^unknown$/i.test(policyLabel) ? " | " + policyLabel : "");
  const subtitle = "Ⓓ " + m(localIP) + " 🅟 " + m(outIP);
  const bodyLines = [
    "🅟 風險控管：" + formatRisk(riskInfo) + " | 類型：" + ipType + " · " + ipSrc,
    "🅟 " + m(outIP) + " " + formatGeo(outInfo?.country_code, outInfo?.city, geoLabel(outInfo)) + " · " + (outInfo?.org || "Unknown")
  ];
  if (entranceInfo) {
    bodyLines.push("Ⓔ " + m(entranceIP) + " " + formatGeo(entranceInfo?.country_code, entranceInfo?.city, geoLabel(entranceInfo)) + " · " + (entranceInfo?.org || "Unknown"));
  }
  bodyLines.push("Ⓓ " + m(localIP) + " " + formatGeo(localInfo?.country_code, localInfo?.city, localZh ? localInfo?.country_name : localInfo?.country_code) + " · " + (localInfo?.org || "Unknown"));
  if (dnsLeak && dnsLeak.leaked && dnsLeak.resolvers) {
    const leakedNames = [...new Set(dnsLeak.resolvers.filter(r => r.isChina).map(r => r.name))];
    bodyLines.push("⚠️ DNS 洩漏! " + leakedNames.join(", "));
  }

  $notification.post(title, subtitle, bodyLines.join("\n"));
  IPLog.log("=== 已傳送通知 ===");
}

// ==================== Stash 獨立卡片 ====================
// 按選定資料源取得中繼資料，不呼叫 Surge API；無 JS 定時器時使用用戶端請求逾時。
// 預設風險和類型取自同一次 IPPure 回應；其他風險源查詢同一 IP，不用另一站點的出口代替。
// 折疊卡片保留簡短地區/電信業者摘要，風險等級與顏色共用 Surge 的設定。
// Android 用標題第二行顯示 IP；iOS 標題也只有一行，改用標記與 IP 同行。
function compactStashLocation(location, local = false) {
  const value = String(location || "").trim();
  const compact = local ? value.replace(/^中[国國]/, "").replace(/^.*?(?:省|自治[区區])/, "")
    .replace(/(?:特[别別]行政[区區]|市).*$/, "") : value.replace(/市$/, "");
  return compact || value;
}

function compactStashOrg(organization) {
  const value = String(organization || "電信業者未知").replace(/^AS\d+\s+/, "")
    .replace(/\s+(?:(?:Co\.?[,]?\s*)?Ltd\.?|Limited|Inc\.?|LLC|Corporation)\.?$/i, "").trim();
  if (isStashiOS) {
    // iOS 正文只有一行，常見中國電信業者用短名稱，包含香港等地區的同品牌出口。
    const carriers = [
      [/中[国國]移[动動]|\bChina\s*Mobile\b/i, "中國移動"],
      [/中[国國][联聯]通|\bChina\s*Unicom\b/i, "中國聯通"],
      [/中[国國][电電]信|\bChina\s*Telecom\b/i, "中國電信"],
      [/中[国國][广廣][电電]|\bChina\s*(?:Broadnet|Broadcasting(?:\s*Network)?)\b/i, "中國廣電"]
    ];
    for (const [pattern, label] of carriers) if (pattern.test(value)) return label;
  }
  return value;
}

function compactStashIPContent({ shortLocation, organization, countryCode }, fallbackCountryCode) {
  const code = countryCode || fallbackCountryCode;
  const location = code === "CN" ? String(shortLocation || "").replace(/[省市]$/, "") : shortLocation;
  let org = compactStashOrg(organization);
  // 按去掉省/市後的地區字數縮短中國電信業者；兩字及以下保留“中國”。
  if (code === "CN" && Array.from(location || "").length > 2) org = org.replace(/^中[国國]/, "");
  return [[flag(code), location || "地區查詢失敗"].filter(Boolean).join(" "), org].join(" · ");
}

async function getStashRiskResult() {
  // IPPure 成功時沿用原生結果；優先選項評分不可用才按同一實測 IP 查詢剩餘來源。
  const info = await getIPPureInfo();
  let pureIP = stashCacheIP(info?.ip);
  const freshScore = typeof info?.fraudScore === "number" ? info.fraudScore :
    (typeof info?.fraudScore === "string" && info.fraudScore.trim() ? Number(info.fraudScore) : NaN);
  let { data } = stashLastGood("risk", pureIP, stashFields({
    score: freshScore, isResidential: info?.isResidential, isBroadcast: info?.isBroadcast
  }));
  const usePure = args.riskApi === "ippure" && Number.isFinite(data.score) && data.score >= 0 && data.score <= 100;
  if (usePure) IPLog.log("風險評分：採用 IPPure");
  let selected = null;
  if (!usePure) {
    if (!pureIP) {
      pureIP = (await fetchOutbound4())?.ip || "";
      data = {}; // 無有效 IP 的 IPPure 欄位不能套到備用探測地址上。
    }
    if (pureIP) selected = await getRiskScore(pureIP);
  }
  const score = usePure ? data.score : selected?.score;
  const source = usePure ? "IPPure" : selected?.source || "Unavailable";
  const valid = Number.isFinite(score) && score >= 0 && score <= 100;
  if (!info && !valid) return null;
  const ipType = typeof data.isResidential === "boolean" ? (data.isResidential ? "住宅 IP" : "機房 IP") : "類型未知";
  const ipSrc = typeof data.isBroadcast === "boolean" ? (data.isBroadcast ? "廣播 IP" : "原生 IP") : "來源未知";
  const { label: level, color } = riskText(valid ? score : null);
  const detail = valid ? formatRisk({ score, source }) : "目前沒有有效評分";
  const typeText = [ipType.replace(/ IP$/, ""), ipSrc.replace(/ IP$/, "")].join(" · ");
  return { ip: pureIP, score, source, valid, level, color, riskText: detail, typeText };
}

async function getStashLocalResult(local) {
  if (local === undefined) local = await httpJSON(CONFIG.urls.localIP, "DIRECT");
  const ip = local?.data?.addr;
  if (!ip) return null;
  const { info } = await getLocalGeo(local);
  return {
    ip, countryCode: info?.country_code,
    location: info && [...new Set([info.country_name, info.region, info.city].filter(Boolean))].join(" "),
    shortLocation: info && compactStashLocation(info.city || info.region || info.country_name, true),
    organization: info?.org
  };
}

async function getStashOutboundResult(includeIPv6, detectedExit) {
  // 折疊卡片不探測 IPv6；地區與電信業者的資料源優先級和首頁、通知一致。
  const ipv6 = includeIPv6 ? fetchOutbound6() : Promise.resolve(null);
  const pure = getIPPureInfo();
  const exit = detectedExit || await fetchOutbound4();
  const outIP = exit?.ip, outRaw = exit?.raw;
  if (!outIP) return null;
  const pureInfo = await pure;
  const sameIPPure = stashCacheIP(pureInfo?.ip) === outIP ? normalizeStashIPPure(pureInfo) : null;
  const probeInfo = sameIPPure?.country_code ? sameIPPure : normalizeIpSb(outRaw);
  const [geography, outIPv6] = await Promise.all([getOutboundGeo(outIP, probeInfo, sameIPPure), ipv6]);
  const { info, reverseDNS } = geography;
  return {
    ip: outIP, ipv6: outIPv6, raw: outRaw, countryCode: info?.country_code,
    location: info && [...new Set([info.city, info.region, geoLabel(info) || info.country_name].filter(Boolean))].join(", "),
    shortLocation: info && compactStashLocation(["HK", "MO", "SG"].includes(info.country_code) ?
      geoLabel(info) : info.city || info.region || geoLabel(info) || info.country_name),
    organization: info?.org || "電信業者未知",
    reverseDNS
  };
}

// 首頁聚合卡片：各項並行檢測，某一項失敗不抹掉其他成功結果。
// 地區和電信業者與折疊卡片使用相同回退順序；風險門檻值及配色保持一致。
async function runStashSummary() {
  const results = await Promise.allSettled([
    getStashRiskResult(), getStashLocalResult(), getStashOutboundResult(true),
    checkDNSLeak(args.proxy || undefined, Date.now() + 1500)
  ]);
  const [risk, local, outbound, dns] = results.map(result => result.status === "fulfilled" ? result.value : null);
  const m = ip => maskIP(ip, args.maskIP);
  const region = info => info?.location ? [flag(info.countryCode), info.location].filter(Boolean).join(" ") : "查詢失敗";
  const lines = [
    "IP 風險控管值：" + (risk?.valid ? formatRisk(risk) : "目前沒有有效評分"),
    "IP 類型：" + (risk?.typeText || "類型未知 · 來源未知"),
    "",
    "本地 IP：" + (local?.ip ? m(local.ip) : "查詢失敗"),
    "地區：" + region(local),
    "電信業者：" + (local?.organization || "Unknown"),
    ""
  ];
  if (outbound?.ipv6) {
    lines.push("出口 IP⁴：" + m(outbound.ip), "出口 IP⁶：" + m(outbound.ipv6));
  } else {
    lines.push("出口 IP：" + (outbound?.ip ? m(outbound.ip) : "查詢失敗"));
  }
  lines.push("地區：" + region(outbound), "電信業者：" + (outbound?.organization || "Unknown"));
  if (outbound?.reverseDNS) lines.push("rDNS：" + (args.maskIP ? "[已隱藏]" : outbound.reverseDNS));
  const resolver = dns?.resolvers?.[0];
  lines.push("", "DNS 解析器：" + (resolver ? m(resolver.ip) : "查詢失敗"));
  if (resolver?.geo) lines.push("DNS 地區：" + resolver.geo);
  // 地區不能證明是否洩漏；proxy 只代表呼叫者顯式指定的策略，不推斷實際節點。
  if (args.proxy) lines.push("指定策略：" + args.proxy);
  return done({
    title: "IP 資訊卡", content: lines.join("\n"),
    backgroundColor: risk?.color || "#9E9E9E", url: "https://ippure.com"
  });
}

async function runStashTile() {
  if (args.tile === "summary") return runStashSummary();
  const tile = stashTiles[args.tile];
  if (!tile) return done({ content: "未知卡片類型" });
  const fail = message => done({
    title: args.mode === "collapsed" && isStashiOS && tile.marker ? tile.marker : tile.title,
    content: message, backgroundColor: "#9E9E9E"
  });
  const render = (lines, color = tile.color, compact = null, url) => done({
    content: lines.filter(Boolean).join("\n"), backgroundColor: color, url,
    ...(args.mode === "collapsed" && compact ? compact : {})
  });
  const m = ip => maskIP(ip, args.maskIP);
  const heading = (detail) => [isStashiOS ? tile.marker : tile.title, detail].filter(Boolean)
    .join(isStashiOS ? " " : "\n");

  if (args.tile === "risk") {
    const result = await getStashRiskResult();
    if (!result) return fail("風險評分檢測失敗");
    const { color, riskText, typeText, valid, score, level } = result;
    const percentText = valid ? score + "% " + level : riskText;
    return render([
      typeText,
      riskText
    ], color, {
      // iOS 標題只放百分比；Android 保留標題第二行，正文均放類型。
      title: heading(percentText),
      content: typeText
    }, args.maskIP === 0 && result.ip ? "https://ippure.com/?ip=" + encodeURIComponent(result.ip) : undefined);
  }

  if (args.tile === "local") {
    const result = await getStashLocalResult();
    if (!result) return fail("無法取得直連公用網路 IP");
    const { ip, countryCode, location, organization } = result;
    return render([
      m(ip),
      location ? [flag(countryCode), location].filter(Boolean).join(" ") : "地區查詢失敗",
      organization || "電信業者未知"
    ], location ? tile.color : "#9E9E9E", {
      title: heading(m(ip)),
      content: location ? compactStashIPContent(result) : "地區查詢失敗"
    }, args.maskIP === 0 ? "https://ippure.com/?ip=" + encodeURIComponent(ip) : undefined);
  }

  if (args.tile === "dns") {
    const detected = await checkDNSLeak(args.proxy || undefined);
    const resolver = detected.resolvers?.[0];
    if (!resolver) return fail("DNS 解析器檢測失敗");
    const info = normalizeIpApi(await httpJSON(CONFIG.urls.ipApi(resolver.ip, "zh-CN")));
    return render([
      m(resolver.ip),
      info ? formatGeo(info.country_code, info.city, info.region, geoLabel(info)) : resolver.geo,
      info?.org || (!resolver.geo ? resolver.name : "")
    ]);
  }

  const result = await getStashOutboundResult(args.mode === "home");
  if (!result) return fail("無法取得出口 IPv4");
  const { ip: outIP, ipv6: outIPv6, raw: outRaw, location, countryCode, organization } = result;
  const lines = [m(outIP), outIPv6 ? "IPv6：" + m(outIPv6) : "",
    location ? [flag(countryCode), location].filter(Boolean).join(" ") : "地區查詢失敗", organization];
  if (args.mode === "home" && result.reverseDNS) lines.push("rDNS：" + (args.maskIP ? "[已隱藏]" : result.reverseDNS));
  if (args.mode === "home" && args.proxy) lines.push("指定策略：" + args.proxy);
  return render(lines, location ? tile.color : "#9E9E9E", {
    title: heading(m(outIP)),
    content: compactStashIPContent(result, outRaw?.country_code)
  });
}

// ==================== 主執行函數 ====================
(async () => {
  try {
  if (isStash && args.task === "logs") {
    IPLog.collect();
    return done({});
  }
  IPLog.log("=== IP 安全檢測開始 (v6.4.15 / " + (isStash ? "Stash / " + (args.task || args.tile) + " / " + args.mode : "Surge") + ") ===");
  if (isStash) IPLog.log("請求線路：本地 DIRECT；出口 " + (args.proxy ? "使用參數指定的策略" : "遵循當前分流（長按測試時使用所選節點）"));
  if (isStash) return args.task === "monitor" ? await runStashMonitor() : await runStashTile();

  // 1. EVENT 觸發時延遲等待網路穩定
  if (args.isEvent && args.eventDelay > 0) {
    IPLog.log("等待網路穩定 " + args.eventDelay + " 秒");
    await wait(args.eventDelay * 1000);
  }

  // 2. 取得本地/出口 IP
  const { localIP, outIP, outIPv6, localRaw, outRaw } = await fetchIPs();

  if (!localIP || !outIP) {
    IPLog.log("IP 取得失敗");
    return done({ title: "IP 取得失敗", content: "無法取得本地或出口 IPv4", icon: "leaf", "icon-color": "#9E9E9E" });
  }
  IPLog.log("本地 IP: " + localIP + ", 出口 IP: " + outIP);

  // 3. EVENT 模式下檢查 IP 是否變化
  if (!checkIPChange(localIP, outIP, outIPv6)) {
    return done({});
  }

  // 4. 並行取得：代理策略+入口 IP、風險評分、IP 類型、地理資訊
  // 入口維持指定資料源查詢；出口使用獨立四級回退。remote_geoapi=ipinfo → ipinfo.io, ipapi/ipapi-zh → ip-api.com(en/zh, http 明文),
  // maxmind/maxmind-zh → GeoLite2(en/zh, 需 key)
  let remoteGeoApi = args.remoteGeoApi;
  if (!["ipinfo", "ipapi", "ipapi-zh", "maxmind", "maxmind-zh"].includes(remoteGeoApi)) {
    IPLog.log("未知 remote_geoapi: " + remoteGeoApi + "，使用 ipapi-zh");
    remoteGeoApi = "ipapi-zh";
  }
  const useIpApi = remoteGeoApi.startsWith("ipapi");
  let useMaxmind = remoteGeoApi.startsWith("maxmind");
  const maxmindZh = remoteGeoApi === "maxmind-zh";
  if (useMaxmind && !args.maxmindKey) {
    IPLog.log("remote_geoapi=maxmind 需要 maxmind_key（account_id:license_key），回落 ipinfo");
    useMaxmind = false;
  }
  const ipApiLang = remoteGeoApi === "ipapi-zh" ? "zh-CN" : "en";
  // 非 ipinfo 資料源時補查 ipinfo：優先取電信業者與 hostname，失敗仍保留可用的地理源欄位。
  const needExtraOrg = useIpApi || useMaxmind;
  const geoHeaders = useMaxmind ? { "Authorization": "Basic " + b64(args.maxmindKey) } : undefined;
  function geoUrl(ip) {
    if (useMaxmind) return CONFIG.urls.maxmindGeo(ip);
    return useIpApi ? CONFIG.urls.ipApi(ip, ipApiLang) : CONFIG.urls.ipInfo(ip);
  }
  function normalizeGeo(data) {
    if (useMaxmind) return normalizeMaxmind(data, maxmindZh);
    return useIpApi ? normalizeIpApi(data) : normalizeIpInfo(data);
  }

  // 先並行發起 geo/risk/流量 API 請求，確保 ip.sb/ipinfo/ip-api 請求完成後再查策略
  // DNS 洩漏檢測需要走代理策略，必須在取得 policy 後執行
  const [riskInfo, ipTypeResult, localGeo, outGeo, trafficResult] = await Promise.all([
    getRiskScore(outIP),
    getIPType(outIP),
    getLocalGeo(localRaw),
    getOutboundGeo(outIP, normalizeIpSb(outRaw)),
    getTrafficStats()
  ]);
  const localInfo = localGeo.info, localZh = localGeo.source !== "ipsb";
  const outInfo = outGeo.info, reverseDNS = outGeo.reverseDNS;
  if (reverseDNS) IPLog.log("反向 DNS: " + reverseDNS);

  // 請求完成後查詢 recent，提高捕獲機率；記錄仍可能缺失，內部會重試並降級。
  const { policy, entranceIP } = await getPolicyAndEntrance();

  // 當前僅在識別到代理策略時探測 DNS 解析器，並將請求指定到該策略。
  const isDirect = !policy || policy === "DIRECT" || policy === "Unknown";
  let dnsLeakResult = null;
  if (!isDirect) {
    dnsLeakResult = await checkDNSLeak(policy);
  } else {
    IPLog.log("當前為直連，跳過 DNS 洩漏檢測");
  }

  // 入口 IP 地理資訊：與出口不同時才查詢
  let entranceInfo = null;
  if (entranceIP && entranceIP !== outIP) {
    IPLog.log("入口 IP: " + entranceIP + " 與出口 IP 不同，查詢入口地理資訊");
    const entrQueries = [httpJSON(geoUrl(entranceIP), null, geoHeaders)];
    if (needExtraOrg) entrQueries.push(httpJSON(CONFIG.urls.ipInfo(entranceIP)));
    const [entrGeoRaw, entrOrgRaw] = await Promise.all(entrQueries);
    entranceInfo = normalizeGeo(entrGeoRaw);
    if (needExtraOrg && entranceInfo && entrOrgRaw) {
      const orgData = normalizeIpInfo(entrOrgRaw);
      if (orgData?.org) entranceInfo.org = orgData.org;
    }
  }

  const riskResult = riskText(riskInfo.score);
  const { ipType, ipSrc } = ipTypeResult;

  // 5. IP 遮蔽：mask_ip=2 鎖定全隱藏；0/1 手動點選切換
  const maskStored = parseInt($persistentStore.read(CONFIG.storeKeys.maskToggle), 10);
  let maskMode = args.maskIP === 2 ? 2 : (Number.isInteger(maskStored) ? maskStored : args.maskIP);
  if (args.maskIP !== 2 && !args.isEvent) {
    const now = Math.floor(Date.now() / 1000);
    const lastRun = parseInt($persistentStore.read(CONFIG.storeKeys.lastRun), 10) || 0;
    $persistentStore.write(String(now), CONFIG.storeKeys.lastRun);
    const elapsed = now - lastRun;
    const interval = args.panelInterval; // 需與 [Panel] update-interval 一致，經 panel_interval 參數傳入（預設 600）
    const tolerance = 15;
    const remainder = elapsed % interval;
    const isAutoRefresh = lastRun > 0 && elapsed > tolerance
      && (remainder <= tolerance || remainder >= interval - tolerance);
    if (lastRun > 0 && !isAutoRefresh) {
      maskMode = maskMode === 1 ? 0 : 1;
      $persistentStore.write(String(maskMode), CONFIG.storeKeys.maskToggle);
    }
  }
  const context = { localZh, maskMode, policy, riskInfo, riskResult, ipType, ipSrc, localIP, localInfo, entranceIP, entranceInfo, outIP, outIPv6, outInfo, dnsLeak: dnsLeakResult, reverseDNS, traffic: trafficResult };

  if (finished) return;
  if (args.isEvent) {
    sendNetworkChangeNotification(context);
    done({});
  } else {
    IPLog.log("=== 面板顯示 ===");
    done({
      title: "代理策略：" + policy,
      content: buildPanelContent(context),
      icon: "leaf.fill",
      "icon-color": riskResult.color
    });
  }
  } catch (e) {
    IPLog.log("未捕獲異常: " + (e.message || e));
    done({ title: "檢測異常", content: e.message || String(e), icon: "leaf", "icon-color": "#9E9E9E" });
  }
})();
