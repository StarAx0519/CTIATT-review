const PRIVATE_IP = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|0\.|255\.)/;

function undefangText(text) {
  let s = String(text || '')
    .replace(/\bhxxps:\/\//gi, 'https://')
    .replace(/\bhxxp:\/\//gi, 'http://')
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[dot\]|\(dot\)|\{dot\}/gi, '.')
    .replace(/\[:\]|\(:\)/g, ':')
    .replace(/\[\/\]/g, '/')
    .replace(/\bhxxps?/gi, 'http');
  
  s = s.replace(/=\r?\n/g, '');
  s = s.replace(/=([0-9A-Fa-f]{2})/g, (_, h) => {
    try {
      return Buffer.from(h, 'hex').toString('latin1');
    } catch {
      return '';
    }
  });
  
  s = s.replace(/(?:[0-9A-Fa-f]{2}=){1,8}[0-9A-Fa-f]{2}(?=[0-9A-Fa-f]{32,})/g, '');
  return s;
}

const DOMAIN_STOP = new Set(
  [
    'the',
    'and',
    'for',
    'with',
    'from',
    'this',
    'that',
    'http',
    'https',
    'www',
    'com',
    'net',
    'org',
    'example',
    'domain',
    'localhost',
    'multipart',
    'content',
    'charset',
    'utf',
    'html',
    'xhtml',
    'schema',
    'xmlns',
    'microsoft',
    'windows',
    'google',
    'w3',
    'w3c'
  ].map((x) => x.toLowerCase())
);

const FILE_EXT_TLDS = new Set(
  [
    'exe',
    'dll',
    'sys',
    'drv',
    'bat',
    'cmd',
    'ps1',
    'vbs',
    'js',
    'jse',
    'wsf',
    'wsh',
    'hta',
    'scr',
    'lnk',
    'jar',
    'msi',
    'msp',
    'doc',
    'docx',
    'docm',
    'xls',
    'xlsx',
    'xlsm',
    'ppt',
    'pptx',
    'pdf',
    'txt',
    'log',
    'cfg',
    'ini',
    'dat',
    'tmp',
    'nls',
    'db',
    'sqlite',
    'zip',
    'rar',
    '7z',
    'gz',
    'json',
    'xml',
    'yml',
    'yaml',
    'png',
    'jpg',
    'jpeg',
    'gif',
    'svg',
    'ico'
  ].map((x) => x.toLowerCase())
);

function isPlausibleDomain(value) {
  const v = String(value || '').toLowerCase();
  if (!v || v.length < 4 || v.length > 253) return false;
  if (!v.includes('.')) return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) return false;
  const labels = v.split('.');
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,24}$/.test(tld)) return false;
  if (FILE_EXT_TLDS.has(tld)) return false;
  if (DOMAIN_STOP.has(labels[0]) && labels.length === 2) return false;
  if (labels.some((l) => !l || l.startsWith('-') || l.endsWith('-'))) return false;
  return true;
}

function cleanFilePath(value) {
  let s = String(value || '');
  
  s = s.replace(/[\u4e00-\u9fff].*$/u, '');
  s = s.replace(/[，。；：、！？【】《》（）""''].*$/u, '');
  s = s.replace(/[,;]\s.*$/, '');
  s = s.replace(/[）)\]}>]+$/, '');
  return s.trim();
}

const IOC_PATTERNS = [
  {
    type: 'sha256',
    
    re: /(?<![0-9A-Fa-f])[a-fA-F0-9]{64}(?![0-9A-Fa-f])/g,
    normalize: (v) => v.toLowerCase()
  },
  {
    type: 'sha1',
    re: /(?<![0-9A-Fa-f])[a-fA-F0-9]{40}(?![0-9A-Fa-f])/g,
    normalize: (v) => v.toLowerCase()
  },
  {
    type: 'md5',
    re: /(?<![0-9A-Fa-f])[a-fA-F0-9]{32}(?![0-9A-Fa-f])/g,
    normalize: (v) => v.toLowerCase()
  },
  {
    type: 'cve',
    re: /\bCVE-\d{4}-\d{4,7}\b/gi,
    normalize: (v) => v.toUpperCase()
  },
  {
    type: 'ipv4',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g,
    normalize: (v) => v
  },
  {
    type: 'ipv6',
    re: /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/g,
    normalize: (v) => v.toLowerCase()
  },
  {
    type: 'url',
    re: /\bhttps?:\/\/[^\s"'<>()\[\]{}]+/gi,
    normalize: (v) => v.replace(/[.,;:)\]}>]+$/g, '')
  },
  {
    type: 'email',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    normalize: (v) => v.toLowerCase()
  },
  {
    type: 'domain',
    re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g,
    normalize: (v) => v.toLowerCase()
  },
  {
    type: 'filepath',
    re: /(?:[A-Za-z]:\\|%(?:LOCALAPPDATA|APPDATA|TEMP|TMP|USERPROFILE|SystemRoot|windir|ProgramFiles(?:\(x86\))?|ProgramData)%\\|\/(?:tmp|var|etc|home|usr|opt)\/)[^\s"'<>|\u4e00-\u9fff]{2,160}/gi,
    normalize: cleanFilePath
  },
  {
    type: 'filename',
    re: /\b[\w.~-]{1,80}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jse|wsf|hta|scr|lnk|jar|msi|docm|xlsm|nls|txt|dat|tmp)\b/gi,
    normalize: (v) => String(v || '').trim()
  },
  {
    type: 'registry',
    re: /(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s"'<>|\u4e00-\u9fff]{3,160}/gi,
    normalize: cleanFilePath
  }
];

function extractIocs(text, opts = {}) {
  const raw = undefangText(text);
  const includePrivate = Boolean(opts.includePrivateIp);
  const seen = new Set();
  const items = [];

  for (const { type, re, normalize } of IOC_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(raw)) !== null) {
      const value = normalize(m[0]);
      if (!value) continue;
      if (type === 'ipv4' && !includePrivate && PRIVATE_IP.test(value)) continue;
      if (type === 'domain' && !isPlausibleDomain(value)) continue;
      const key = `${type}|${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      items.push({ type, value, source: 'regex' });
    }
  }

  return items;
}

function summarizeIocs(iocs) {
  const byType = {};
  const byCategory = {};
  for (const i of iocs || []) {
    byType[i.type] = (byType[i.type] || 0) + 1;
    const cat = i.category || i.type;
    byCategory[cat] = (byCategory[cat] || 0) + 1;
  }
  return {
    total: (iocs || []).length,
    byType,
    byCategory
  };
}

function mergeIocs(...lists) {
  const seen = new Set();
  const out = [];
  for (const list of lists) {
    for (const i of list || []) {
      const key = `${i.category || i.type}|${i.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(i);
    }
  }
  return out;
}

function groupIocsByColumns(iocs, displayColumns, typeToColumn) {
  const cols = displayColumns || [];
  const map = typeToColumn || {};
  const buckets = {};
  for (const c of cols) {
    buckets[c.key || c] = [];
  }
  const seen = new Set();
  for (const ioc of iocs || []) {
    const col =
      (ioc.category && buckets[ioc.category] ? ioc.category : null) ||
      map[ioc.type] ||
      (buckets[ioc.type] ? ioc.type : null);
    if (!col || !buckets[col]) continue;
    const val = String(ioc.value || '').trim();
    if (!val) continue;
    const key = `${col}|${val}`;
    if (seen.has(key)) continue;
    seen.add(key);
    buckets[col].push(val);
  }
  return buckets;
}

const IOC_SAMPLE_CAPS = {
  domain: 6,
  ipv4: 5,
  ipv6: 3,
  url: 5,
  sha256: 4,
  sha1: 4,
  md5: 2,
  email: 4,
  cve: 4,
  vulnerability: 4,
  filepath: 2,
  registry: 2,
  filename: 2
};
const IOC_SAMPLE_TOTAL_CAP = 32;
const IOC_TYPE_PRIORITY = [
  'domain',
  'ipv4',
  'ipv6',
  'url',
  'sha256',
  'sha1',
  'md5',
  'email',
  'cve',
  'vulnerability',
  'filepath',
  'registry',
  'filename'
];
const PLACEHOLDER_DOMAIN =
  /^(localhost|local|example\.(com|org|net)|test\.(com|org|net)|invalid|localdomain)$/i;
const HASH_RANK = { sha256: 3, sha1: 2, md5: 1 };

function normalizeIocType(ioc) {
  const t = String(ioc.type || ioc.category || '').toLowerCase();
  if (t === 'ip') return /^[\d.]+$/.test(String(ioc.value || '')) ? 'ipv4' : 'ipv6';
  if (t === 'malware') {
    const v = String(ioc.value || '');
    if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
    if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1';
    if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
    return 'sha1';
  }
  return t;
}

function urlHost(u) {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch (_) {
    const m = String(u || '').match(/^https?:\/\/([^/:?#]+)/i);
    return m ? m[1].toLowerCase() : '';
  }
}

function shortenUrl(u) {
  const s = String(u || '').replace(/#.*$/, '');
  const q = s.indexOf('?');
  if (q >= 0 && s.length - q > 120) return `${s.slice(0, q + 120)}…`;
  if (s.length > 180) return `${s.slice(0, 180)}…`;
  return s;
}

function collectIocPool(row) {
  const pool = [];
  const seen = new Set();
  const push = (type, value, category) => {
    const v = String(value || '').trim();
    if (!v) return;
    const t = normalizeIocType({ type, category, value: v });
    if (!t || !IOC_SAMPLE_CAPS[t]) return;
    const key = `${t}|${v.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    pool.push({ type: t, value: v, category: category || t });
  };

  for (const i of row.iocs || []) {
    push(i.type, i.value, i.category);
  }
  const cols = row.iocColumns || {};
  for (const [cat, vals] of Object.entries(cols)) {
    if (!Array.isArray(vals)) continue;
    for (const v of vals) push(cat, v, cat);
  }
  return pool;
}

function isPrivateIpv4(ip) {
  return PRIVATE_IP.test(String(ip || ''));
}

function pickRepresentativeIocs(row, opts = {}) {
  const caps = { ...IOC_SAMPLE_CAPS, ...(opts.caps || {}) };
  const totalCap = opts.totalCap || IOC_SAMPLE_TOTAL_CAP;
  const pool = collectIocPool(row || {});

  const bestHash = new Map();
  for (const i of pool) {
    if (!HASH_RANK[i.type]) continue;
    const hex = i.value.toLowerCase();
    const prev = bestHash.get(hex);
    if (!prev || HASH_RANK[i.type] > HASH_RANK[prev.type]) bestHash.set(hex, i);
  }

  const byType = {};
  for (const i of pool) {
    if (HASH_RANK[i.type]) {
      const keep = bestHash.get(i.value.toLowerCase());
      if (!keep || keep.type !== i.type) continue;
    }
    if (i.type === 'domain') {
      if (!i.value.includes('.') || PLACEHOLDER_DOMAIN.test(i.value)) continue;
    }
    let item = i;
    if (i.type === 'url') {
      const shortened = shortenUrl(i.value);
      if (!/^https?:\/\//i.test(shortened)) continue;
      item = { ...i, value: shortened };
    }
    if (!byType[item.type]) byType[item.type] = [];
    byType[item.type].push(item);
  }

  for (const t of Object.keys(byType)) {
    byType[t].sort((a, b) => String(a.value).localeCompare(String(b.value)));
  }

  if (byType.ipv4) {
    const pub = byType.ipv4.filter((x) => !isPrivateIpv4(x.value));
    const priv = byType.ipv4.filter((x) => isPrivateIpv4(x.value)).slice(0, 2);
    byType.ipv4 = [...pub, ...priv];
  }

  if (byType.url) {
    const byHost = new Map();
    for (const u of byType.url) {
      const h = urlHost(u.value) || '_';
      if (!byHost.has(h)) byHost.set(h, []);
      byHost.get(h).push(u);
    }
    const hosts = [...byHost.keys()].sort();
    const diversified = [];
    for (const h of hosts) diversified.push(byHost.get(h)[0]);
    for (const h of hosts) {
      for (const extra of byHost.get(h).slice(1)) {
        if (diversified.length >= (caps.url || 5) * 2) break;
        diversified.push(extra);
      }
    }
    byType.url = diversified;
  }

  const selected = [];
  const selectedByType = {};
  const pushed = new Set();

  for (const type of IOC_TYPE_PRIORITY) {
    const list = byType[type] || [];
    const cap = caps[type] || 0;
    if (!cap || !list.length) continue;
    let n = 0;
    for (const item of list) {
      if (selected.length >= totalCap) break;
      if (n >= cap) break;
      const key = `${item.type}|${item.value.toLowerCase()}`;
      if (pushed.has(key)) continue;
      pushed.add(key);
      selected.push({ type: item.type, value: item.value });
      if (!selectedByType[item.type]) selectedByType[item.type] = [];
      selectedByType[item.type].push(item.value);
      n += 1;
    }
  }

  const totalAvailable = pool.length;
  return {
    selected,
    byType: selectedByType,
    meta: {
      available: totalAvailable,
      sampled: selected.length,
      caps,
      totalCap,
      truncated: selected.length < totalAvailable
    }
  };
}

module.exports = {
  extractIocs,
  undefangText,
  summarizeIocs,
  mergeIocs,
  groupIocsByColumns,
  pickRepresentativeIocs,
  IOC_PATTERNS,
  IOC_SAMPLE_CAPS,
  IOC_SAMPLE_TOTAL_CAP
};
