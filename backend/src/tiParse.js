const { extractIocs } = require('./iocExtract');
const {
  recoverCtiJsonText,
  synthesizeCtiFieldsFromText,
  isCtiLike
} = require('./ctiRecover');

function tryJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (e) {
    return { ok: false, error: e };
  }
}

function asArray(v) {
  if (Array.isArray(v)) return v;
  if (v == null) return [];
  return [v];
}

function pickText(obj) {
  const parts = [
    obj.title,
    obj.name,
    obj.summary,
    obj.description,
    obj.desc,
    obj.comment,
    obj.details,
    obj.pattern,
    obj.value,
    obj.indicator,
    obj.threat,
    obj.intel,
    obj.text,
    obj.message
  ]
    .filter(Boolean)
    .map(String);
  return parts.join('\n');
}

function normalizeTiItem(raw, index) {
  const obj = raw && typeof raw === 'object' ? { ...raw } : { text: String(raw || '') };
  const title =
    obj.title ||
    obj.name ||
    obj.indicator ||
    obj.id ||
    obj.type ||
    `情报条目-${index + 1}`;
  const description = pickText(obj) || String(obj.text || '');
  const threatType =
    obj.threatType ||
    obj.attackType ||
    obj.type ||
    obj.category ||
    obj.labels?.[0] ||
    obj.tags?.[0] ||
    '';
  const explicitTechniqueId =
    obj.techniqueId || obj.technique || obj.mitre_attack_id || obj.external_id || null;
  const explicitTacticId = obj.tacticId || obj.tactic || null;
  const techniqueIds = asArray(obj.techniqueIds || obj.techniques)
    .map((x) => String(x || '').trim().toUpperCase())
    .filter((x) => /^T\d{4}/.test(x));

  let structuredIocs = [];
  if (Array.isArray(obj.iocs)) {
    structuredIocs = obj.iocs.map((x) =>
      typeof x === 'string'
        ? { type: 'unknown', value: x }
        : {
            type: x.type || x.indicator_type || 'unknown',
            category: x.category || undefined,
            value: x.value || x.indicator || ''
          }
    );
  } else if (Array.isArray(obj.indicators)) {
    structuredIocs = obj.indicators.map((x) =>
      typeof x === 'string'
        ? { type: 'unknown', value: x }
        : {
            type: x.type || x.indicator_type || 'unknown',
            category: x.category || undefined,
            value: x.value || x.indicator || ''
          }
    );
  }

  return {
    id: obj.id || obj.uuid || obj.sourceId || `ti-${index + 1}`,
    sourceId: obj.sourceId || obj.rid || obj.id || obj.uuid || undefined,
    title: String(title),
    description: String(description),
    threatType: String(threatType || ''),
    tags: asArray(obj.tags || obj.labels).map(String),
    source: obj.source || obj.feed || obj.created_by || '',
    timestamp: obj.timestamp || obj.created || obj.modified || obj.date || null,
    explicitTechniqueId,
    explicitTacticId,
    techniqueIds: techniqueIds.length
      ? [...new Set(techniqueIds)]
      : explicitTechniqueId
        ? [String(explicitTechniqueId).toUpperCase()]
        : [],
    structuredIocs: structuredIocs.filter((x) => x && x.value),
    raw: obj
  };
}

function mapMispType(t) {
  const s = String(t || '').toLowerCase();
  if (s.includes('sha256')) return 'sha256';
  if (s.includes('sha1')) return 'sha1';
  if (s.includes('md5')) return 'md5';
  if (s.includes('ip')) return 'ipv4';
  if (s.includes('domain') || s.includes('hostname')) return 'domain';
  if (s.includes('url')) return 'url';
  if (s.includes('email')) return 'email';
  if (s.includes('filename')) return 'filepath';
  return s || 'unknown';
}

function inferHashType(value) {
  const v = String(value || '').trim();
  if (/^[a-fA-F0-9]{64}$/.test(v)) return 'sha256';
  if (/^[a-fA-F0-9]{40}$/.test(v)) return 'sha1';
  if (/^[a-fA-F0-9]{32}$/.test(v)) return 'md5';
  return 'hash';
}

function parseStix(data) {
  const objects = Array.isArray(data) ? data : data.objects || asArray(data);
  const items = [];
  for (const o of objects) {
    if (!o || typeof o !== 'object') continue;
    const t = o.type || '';
    if (
      t === 'indicator' ||
      t === 'malware' ||
      t === 'attack-pattern' ||
      t === 'threat-report' ||
      t === 'report'
    ) {
      const ext = (o.external_references || []).find(
        (r) => r.source_name === 'mitre-attack' || r.external_id
      );
      items.push(
        normalizeTiItem(
          {
            id: o.id,
            title: o.name || o.pattern || t,
            description: [o.description, o.pattern, o.summary].filter(Boolean).join('\n'),
            threatType: t,
            techniqueId: ext?.external_id || null,
            labels: o.labels,
            tags: o.labels
          },
          items.length
        )
      );
    }
  }
  return items;
}

function parseMisp(data) {
  const event = data.Event || data.event || data;
  const attrs = event.Attribute || event.attribute || data.Attribute || [];
  const items = [];
  const info = event.info || event.Info || 'MISP Event';
  if (Array.isArray(attrs) && attrs.length) {
    for (const a of attrs) {
      items.push(
        normalizeTiItem(
          {
            id: a.uuid || a.id,
            title: `${a.type || 'ioc'}: ${a.value}`,
            description: a.comment || a.value,
            type: a.type,
            iocs: [{ type: mapMispType(a.type), value: a.value }],
            tags: (a.Tag || []).map((t) => t.name || t)
          },
          items.length
        )
      );
    }
  } else {
    items.push(normalizeTiItem({ title: info, description: info, threatType: 'misp' }, 0));
  }
  return items;
}

function parseCtiReport(data) {
  const report = data.CTI_Report || data.cti_report || {};
  const iocBlock = data.IOC || data.ioc || {};
  const ttp = data.TTP || data.ttp || {};

  const structuredIocs = [];
  const pushList = (arr, category) => {
    for (const v of asArray(arr)) {
      if (v == null || v === '') continue;
      const value = String(v).trim();
      if (!value) continue;
      let type = category;
      if (category === 'malware' || category === 'hash') type = inferHashType(value);
      else if (category === 'ip') type = value.includes(':') ? 'ipv6' : 'ipv4';
      else if (category === 'vulnerability') type = /^CVE-/i.test(value) ? 'cve' : 'vulnerability';
      else if (category === 'filename') type = 'filename';
      structuredIocs.push({ category, type, value });
    }
  };

  pushList(iocBlock.malware, 'malware');
  pushList(iocBlock.domain, 'domain');
  pushList(iocBlock.ip, 'ip');
  pushList(iocBlock.url, 'url');
  pushList(iocBlock.vulnerability, 'vulnerability');
  pushList(iocBlock.registry, 'registry');
  pushList(iocBlock.filepath, 'filepath');
  pushList(iocBlock.filename, 'filename');
  pushList(iocBlock.email, 'email');

  const techniques = [...asArray(ttp.technique), ...asArray(ttp.subtechnique)]
    .map((x) => String(x || '').trim().toUpperCase())
    .filter((x) => {
      const m = x.match(/^T(\d{4})(?:\.\d{3})?$/);
      return m && Number(m[1]) >= 1000;
    });
  const uniqueTechs = [...new Set(techniques)];
  const tactics = asArray(ttp.tactic)
    .map((x) => String(x || '').trim().toUpperCase())
    .filter(Boolean);

  const title = report.title || report.rid || report.id || 'CTI 报告';
  const rid = report.rid || report.id || '';
  const attacker = report.attacker_label || report.attacker || '';
  const threatType = attacker || 'cti-report';
  const tags = ['CTI_Report', attacker, rid].filter(Boolean);
  const descParts = [
    title,
    attacker ? `攻击组织/标签: ${attacker}` : '',
    rid ? `报告编号: ${rid}` : '',
    uniqueTechs.length ? `ATT&CK 技术: ${uniqueTechs.join(', ')}` : '',
    tactics.length ? `ATT&CK 战术: ${tactics.join(', ')}` : '',
    structuredIocs.length ? `IOC 数量: ${structuredIocs.length}` : ''
  ].filter(Boolean);

  return [
    normalizeTiItem(
      {
        ...(rid ? { id: rid } : {}),
        title,
        description: descParts.join('\n'),
        threatType,
        tags,
        techniqueId: uniqueTechs[0] || null,
        techniqueIds: uniqueTechs,
        tacticId: tactics[0] || null,
        iocs: structuredIocs,
        source: 'CTI_Report',
        sourceId: rid || undefined
      },
      0
    )
  ];
}

function isCtiReport(data) {
  return isCtiLike(data);
}

function looksLikeIntelObject(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  if (o.CTI_Report || o.cti_report || o.IOC || o.TTP) return true;
  if (o.title || o.name || o.description || o.summary) return true;
  if (o.iocs || o.indicators || o.pattern) return true;
  if (o.threatType || o.attackType) return true;
  if ((o.type || o.indicator_type) && (o.value || o.indicator)) return true;
  return false;
}

function parseNdjson(text) {
  const items = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.length < 2) continue;
    if (!(t.startsWith('{') || t.startsWith('['))) continue;
    const j = tryJson(t);
    if (!j.ok) continue;
    const val = j.value;
    if (Array.isArray(val)) {
      for (const x of val) {
        if (looksLikeIntelObject(x)) items.push(normalizeTiItem(x, items.length));
      }
      continue;
    }
    if (looksLikeIntelObject(val)) items.push(normalizeTiItem(val, items.length));
  }
  return items;
}

function parseCefLike(text) {
  const items = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!/CEF:\d+\|/i.test(line) && !/LEEF:\d+\|/i.test(line)) continue;
    items.push(
      normalizeTiItem(
        {
          title: line.slice(0, 80),
          description: line,
          threatType: /CEF/i.test(line) ? 'cef' : 'leef'
        },
        items.length
      )
    );
  }
  return items;
}

function parseXmlHints(text) {
  const blocks =
    text.match(
      /<(?:Indicator|indicator|Observable|observable|FileItem|Network|STIX_Package|stix:Indicator)[\s\S]*?<\/[^>]+>/gi
    ) || [];
  if (!blocks.length) return [];
  return blocks.map((b, i) =>
    normalizeTiItem(
      {
        title: `XML块-${i + 1}`,
        description: b.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(),
        threatType: 'openioc-xml'
      },
      i
    )
  );
}

function parseCsvIoc(text) {
  const lines = String(text || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length < 1) return [];
  const delim = lines[0].includes('\t') ? '\t' : lines[0].includes(';') ? ';' : ',';
  const headers = lines[0].split(delim).map((h) => h.trim().toLowerCase().replace(/^"|"$/g, ''));
  const looksHeader = headers.some((h) =>
    /type|value|ioc|indicator|ip|domain|hash|url|cve|title|desc/.test(h)
  );
  const start = looksHeader ? 1 : 0;
  const col = (name) => {
    const i = headers.indexOf(name);
    return i >= 0 ? i : -1;
  };
  const items = [];
  for (let i = start; i < lines.length; i++) {
    const cols = lines[i].split(delim).map((c) => c.trim().replace(/^"|"$/g, ''));
    const row = {};
    if (looksHeader) {
      headers.forEach((h, idx) => {
        row[h] = cols[idx];
      });
    } else {
      row.type = cols[0];
      row.value = cols[1];
      row.title = cols[2];
      row.description = cols[3];
    }
    const value = row.value || row.ioc || row.indicator || cols[1];
    if (!value) continue;
    const type = mapMispType(row.type || row.kind || 'unknown');
    items.push(
      normalizeTiItem(
        {
          title: row.title || row.name || `${type}: ${value}`,
          description: row.description || row.desc || row.comment || value,
          threatType: row.threatType || type,
          iocs: [{ type, value }]
        },
        items.length
      )
    );
  }
  return items;
}

function parseNarrativeBlocks(text) {
  const parts = String(text || '')
    .split(/\n\s*---+\s*\n|\n{3,}/)
    .map((p) => p.trim())
    .filter((p) => p.length > 8);
  if (!parts.length && text.trim()) parts.push(text.trim());

  {
    const whole = parts.join('\n\n');
    const syn = synthesizeCtiFieldsFromText(whole);
    if (syn && (syn.techniqueIds.length >= 2 || syn.iocs.length >= 3)) {
      return [
        normalizeTiItem(
          {
            title: syn.title,
            description: syn.description,
            threatType: syn.threatType,
            techniqueId: syn.techniqueId,
            techniqueIds: syn.techniqueIds,
            iocs: syn.iocs,
            source: syn.source,
            tags: ['text-synthesized']
          },
          0
        )
      ];
    }
  }

  return parts.map((p, i) => {
    const syn = synthesizeCtiFieldsFromText(p);
    const first = p.split(/\r?\n/)[0].slice(0, 80);
    return normalizeTiItem(
      {
        title: (syn && syn.title) || first,
        description: p,
        threatType: (syn && syn.threatType) || 'narrative',
        techniqueId: syn?.techniqueId || null,
        techniqueIds: syn?.techniqueIds || [],
        iocs: syn?.iocs || [],
        source: syn?.source || 'narrative'
      },
      i
    );
  });
}

function parseThreatIntelText(text) {
  let raw = String(text || '').trim();
  if (!raw) return [];

  if (!raw.trimStart().startsWith('{')) {
    const recovered = recoverCtiJsonText(raw);
    if (recovered) raw = recovered;
  } else {
    const recovered = recoverCtiJsonText(raw);
    if (recovered) {
      const probe = tryJson(raw);
      if (!probe.ok) raw = recovered;
    }
  }

  const j = tryJson(raw);
  if (j.ok) {
    const data = j.value;
    if (isCtiReport(data)) {
      const cti = parseCtiReport(data);
      if (cti.length) return cti;
    }
    if (data.type === 'bundle' || Array.isArray(data.objects) || data.spec_version) {
      const stix = parseStix(data);
      if (stix.length) return stix;
    }
    if (data.Event || data.Attribute || data.event) {
      const misp = parseMisp(data);
      if (misp.length) return misp;
    }
    if (Array.isArray(data)) {
      if (data.length && data.every((x) => isCtiReport(x))) {
        return data.flatMap((x) => parseCtiReport(x));
      }
      return data.map((x, i) => normalizeTiItem(x, i));
    }
    if (Array.isArray(data.items) || Array.isArray(data.indicators) || Array.isArray(data.data)) {
      const arr = data.items || data.indicators || data.data;
      return arr.map((x, i) => normalizeTiItem(x, i));
    }
    return [normalizeTiItem(data, 0)];
  }

  const nd = parseNdjson(raw);
  if (nd.length >= 2) {
    const nonEmpty = raw.split(/\r?\n/).filter((l) => l.trim()).length;
    if (nd.length >= 5 || (nonEmpty > 0 && nd.length / nonEmpty >= 0.5)) return nd;
  }

  const cef = parseCefLike(raw);
  if (cef.length) return cef;

  if (
    /<(?:Indicator|indicator|Observable|observable|FileItem|STIX_Package|stix:Indicator)\b/i.test(
      raw
    )
  ) {
    const xml = parseXmlHints(raw);
    if (xml.length) return xml;
  }

  const firstLine = raw.split(/\r?\n/)[0] || '';
  if (
    (firstLine.includes(',') || firstLine.includes('\t') || firstLine.includes(';')) &&
    /type|value|ioc|ip|hash|domain|url|indicator/i.test(firstLine)
  ) {
    const csv = parseCsvIoc(raw);
    if (csv.length) return csv;
  }

  const lines = raw.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length >= 3) {
    const iocHits = lines.filter((l) => extractIocs(l).length > 0).length;
    if (iocHits / lines.length >= 0.6) {
      return lines.map((l, i) => {
        const iocs = extractIocs(l);
        return normalizeTiItem(
          {
            title: iocs[0] ? `${iocs[0].type}: ${iocs[0].value}` : l.slice(0, 60),
            description: l,
            threatType: 'ioc-list',
            iocs
          },
          i
        );
      });
    }
  }

  return parseNarrativeBlocks(raw);
}

module.exports = {
  parseThreatIntelText,
  normalizeTiItem,
  parseStix,
  parseMisp,
  parseCsvIoc,
  parseCtiReport,
  isCtiReport
};
