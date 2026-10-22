const { extractIocs } = require('./iocExtract');

function tryJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (e) {
    return { ok: false, error: e };
  }
}

function countIocBlock(ioc) {
  if (!ioc || typeof ioc !== 'object') return 0;
  let n = 0;
  for (const v of Object.values(ioc)) {
    if (Array.isArray(v)) n += v.filter((x) => x != null && String(x).trim()).length;
    else if (v != null && String(v).trim()) n += 1;
  }
  return n;
}

function countTtpIds(ttp) {
  if (!ttp || typeof ttp !== 'object') return 0;
  const ids = [...(ttp.technique || []), ...(ttp.subtechnique || []), ...(ttp.tactic || [])];
  return ids.filter((x) => x != null && String(x).trim()).length;
}

function isCtiLike(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
  const report = data.CTI_Report || data.cti_report;
  const ioc = data.IOC || data.ioc;
  const ttp = data.TTP || data.ttp;
  if (report && typeof report === 'object') {
    if (report.title || report.rid || report.id || report.attacker_label) return true;
  }
  if (ioc && ttp) {
    return countIocBlock(ioc) > 0 || countTtpIds(ttp) > 0;
  }
  return false;
}

function hasStructuredCtiMarker(text) {
  const raw = String(text || '');
  return (
    /"CTI_Report"\s*:/i.test(raw) ||
    /\bCTI_Report\s*:/i.test(raw) ||
    /"IOC"\s*:/i.test(raw) ||
    /"TTP"\s*:/i.test(raw) ||
    /"cti_report"\s*:/i.test(raw)
  );
}

function sanitizePdfJsonNoise(text) {
  return String(text || '')
    .replace(/[\u00D0\u00A0\u2028\u2029\u000B\u000C]/g, '\n')
    .replace(/\r\n/g, '\n')
    .replace(/[\uFEFF\u200B-\u200D]/g, '')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'");
}

function bucketExtractedIocs(rawText) {
  const buckets = {
    malware: [],
    domain: [],
    ip: [],
    url: [],
    vulnerability: [],
    registry: [],
    filepath: [],
    filename: [],
    email: []
  };
  for (const x of extractIocs(rawText) || []) {
    const v = String(x.value || '').trim();
    if (!v) continue;
    if (['md5', 'sha1', 'sha256', 'hash'].includes(x.type)) buckets.malware.push(v);
    else if (x.type === 'ipv4' || x.type === 'ipv6') buckets.ip.push(v);
    else if (x.type === 'domain') buckets.domain.push(v);
    else if (x.type === 'url') buckets.url.push(v);
    else if (x.type === 'cve' || x.type === 'vulnerability') buckets.vulnerability.push(v);
    else if (x.type === 'email') buckets.email.push(v);
    else if (x.type === 'registry') buckets.registry.push(v);
    else if (x.type === 'filepath') buckets.filepath.push(v);
    else if (x.type === 'filename') buckets.filename.push(v);
  }
  for (const k of Object.keys(buckets)) {
    buckets[k] = [...new Set(buckets[k])];
  }
  return buckets;
}

function rebuildCtiFromFragments(rawText) {
  const raw = sanitizePdfJsonNoise(rawText);
  if (!hasStructuredCtiMarker(raw)) return null;

  const pickStr = (keys) => {
    for (const k of keys) {
      const re = new RegExp(`"${k}"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`, 'i');
      const m = raw.match(re);
      if (m) return m[1];
    }
    return '';
  };

  const pickList = (key) => {
    const re = new RegExp(`"${key}"\\s*:\\s*\\[([\\s\\S]*?)\\]`, 'i');
    const m = raw.match(re);
    if (!m) return [];
    const body = m[1];
    const vals = [];
    const strRe = /"((?:\\.|[^"\\])*)"/g;
    let sm;
    while ((sm = strRe.exec(body)) !== null) {
      const v = sm[1].trim();
      if (v) vals.push(v);
    }
    return vals;
  };

  const title = pickStr(['title']);
  const rid = pickStr(['rid', 'id']);
  const attacker = pickStr(['attacker_label', 'attacker']);
  let malware = pickList('malware');
  let domain = pickList('domain');
  let ip = pickList('ip');
  let url = pickList('url');
  let vulnerability = pickList('vulnerability');
  let registry = pickList('registry');
  let filepath = pickList('filepath');
  let filename = pickList('filename');
  let email = pickList('email');

  const tactic = pickList('tactic');
  const technique = pickList('technique');
  const subtechnique = pickList('subtechnique');
  const hasJsonTechs = tactic.length + technique.length + subtechnique.length > 0;

  let hasIoc =
    malware.length +
      domain.length +
      ip.length +
      url.length +
      vulnerability.length +
      registry.length +
      filepath.length +
      filename.length +
      email.length >
    0;

  
  if (!hasIoc) {
    const filled = bucketExtractedIocs(raw);
    malware = filled.malware;
    domain = filled.domain;
    ip = filled.ip;
    url = filled.url;
    vulnerability = filled.vulnerability;
    registry = filled.registry;
    filepath = filled.filepath;
    filename = filled.filename;
    email = filled.email;
    hasIoc =
      malware.length +
        domain.length +
        ip.length +
        url.length +
        vulnerability.length +
        registry.length +
        filepath.length +
        filename.length +
        email.length >
      0;
  }

  
  if (!hasIoc && !hasJsonTechs && !title && !rid && !attacker) return null;

  const techs = [...new Set([...technique, ...subtechnique])];

  const rebuilt = {
    CTI_Report: {
      ...(rid ? { rid } : {}),
      title: title || rid || 'Recovered CTI Report',
      attacker_label: attacker || ''
    },
    IOC: {
      malware,
      domain,
      ip,
      url,
      vulnerability,
      registry,
      filepath,
      filename,
      email
    },
    TTP: {
      tactic: tactic.length ? tactic : [],
      technique: technique.length ? technique : techs.filter((t) => !t.includes('.')),
      subtechnique: subtechnique.length ? subtechnique : techs.filter((t) => t.includes('.'))
    }
  };

  if (!isCtiLike(rebuilt)) return null;
  return JSON.stringify(rebuilt);
}

function recoverCtiJsonText(rawText) {
  const raw = String(rawText || '').trim();
  if (!raw) return null;

  const candidates = [];
  const push = (s) => {
    if (s && s.trim()) candidates.push(s.trim());
  };

  push(raw);
  push(sanitizePdfJsonNoise(raw));

  const withoutPrefix = raw.replace(/^PDF[^\n]*\n+/i, '');
  push(withoutPrefix);
  push(sanitizePdfJsonNoise(withoutPrefix));

  for (const base of [...candidates]) {
    const start = base.indexOf('{');
    const end = base.lastIndexOf('}');
    if (start >= 0 && end > start) {
      const slice = base.slice(start, end + 1);
      push(slice);
      push(sanitizePdfJsonNoise(slice));
      push(sanitizePdfJsonNoise(slice).replace(/\n+/g, ' '));
      push(
        sanitizePdfJsonNoise(slice)
          .replace(/\n+/g, '\n')
          .replace(/,\s*}/g, '}')
          .replace(/,\s*]/g, '[')
      );
    }
  }

  const seen = new Set();
  for (const c of candidates) {
    if (seen.has(c)) continue;
    seen.add(c);
    const j = tryJson(c);
    if (j.ok && isCtiLike(j.value)) {
      return JSON.stringify(j.value);
    }
  }

  const rebuilt = rebuildCtiFromFragments(raw);
  if (rebuilt) return rebuilt;

  return null;
}

function synthesizeCtiFieldsFromText(text, titleHint = '') {
  const raw = String(text || '');
  const techniqueIds = [];
  const re = /\b(T\d{4}(?:\.\d{3})?)\b/gi;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const id = m[1].toUpperCase();
    const num = Number(id.slice(1, 5));
    if (num >= 1000) techniqueIds.push(id);
  }
  const uniqueTechs = [...new Set(techniqueIds)];
  const iocs = extractIocs(raw);
  const structured = iocs.map((x) => {
    if (['md5', 'sha1', 'sha256', 'hash'].includes(x.type)) {
      return { ...x, category: 'malware' };
    }
    if (x.type === 'ipv4' || x.type === 'ipv6') {
      return { ...x, category: 'ip' };
    }
    if (x.type === 'cve') {
      return { ...x, category: 'vulnerability' };
    }
    return { ...x, category: x.type };
  });

  if (!uniqueTechs.length && !structured.length) return null;

  const titleMatch =
    raw.match(/"title"\s*:\s*"([^"]+)"/i) ||
    raw.match(/^PDF\s*威胁情报报告:\s*(.+)$/im) ||
    raw.match(/title["\s:]+([^\n]{8,120})/i);
  const attackerMatch =
    raw.match(/"attacker_label"\s*:\s*"([^"]+)"/i) ||
    raw.match(/\b(APT\d+|Turla|Dukes|海莲花)\b/i);

  return {
    title: (titleMatch && titleMatch[1].trim()) || titleHint || '威胁情报',
    threatType: (attackerMatch && attackerMatch[1]) || 'cti-report',
    techniqueIds: uniqueTechs,
    techniqueId: uniqueTechs[0] || null,
    iocs: structured,
    description: raw.slice(0, 12000),
    source: 'text-synthesized'
  };
}

module.exports = {
  recoverCtiJsonText,
  synthesizeCtiFieldsFromText,
  sanitizePdfJsonNoise,
  rebuildCtiFromFragments,
  isCtiLike,
  hasStructuredCtiMarker
};
