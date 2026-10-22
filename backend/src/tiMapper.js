const { findBestTechniqueHit } = require('./techniqueLexicon');
const { extractIocs, summarizeIocs, mergeIocs, groupIocsByColumns } = require('./iocExtract');
const { getMappingKnowledge } = require('./knowledgeLoader');

const QUALITY_LEVELS = [
  { min: 0.9, level: 'excellent', label: '高置信度映射' },
  { min: 0.8, level: 'good', label: '可靠映射' },
  { min: 0.7, level: 'fair', label: '需人工复核' },
  { min: 0, level: 'poor', label: '建议补充分析' }
];

const METHOD_LABELS = {
  explicit: '文中标明',
  rule: '类型规则',
  heuristic: '关键词启发',
  vector: '向量相似',
  llm: '大模型辅助',
  fallback: '默认设定'
};

function knowledge() {
  return getMappingKnowledge();
}

function getTiTypeRules() {
  return knowledge().tiTypeRules || {};
}

function getTechniqueAliases() {
  return knowledge().techniqueAliases || {};
}

function getTechniqueTacticHints() {
  return knowledge().techniqueTacticHints || {};
}

function getTypeAliases() {
  return knowledge().typeAliases || {};
}

function getFallbackTechniqueId() {
  return knowledge().fallbackTechniqueId || 'T1071';
}

function normalizeTechniqueId(id) {
  if (!id) return null;
  let s = String(id).trim().toUpperCase();
  if (!s.startsWith('T')) s = `T${s}`;
  const m = s.match(/^(T(\d{4})(?:\.\d{3})?)/);
  if (!m) return null;
  
  if (Number(m[2]) < 1000) return null;
  return m[1];
}

function resolveTechniqueId(attck, rawId) {
  const id = normalizeTechniqueId(rawId);
  if (!id) return null;
  if (attck.techniqueById?.[id]) {
    return { id, resolvedFrom: null, inKb: true };
  }
  if (id.includes('.')) {
    const parent = id.split('.')[0];
    if (attck.techniqueById?.[parent]) {
      return { id: parent, resolvedFrom: id, inKb: true };
    }
  }
  const aliases = getTechniqueAliases();
  const alias = aliases[id] || aliases[id.split('.')[0]];
  if (alias) {
    const aliasId = normalizeTechniqueId(alias);
    if (aliasId && attck.techniqueById?.[aliasId]) {
      return { id: aliasId, resolvedFrom: id, inKb: true };
    }
    if (aliasId && aliasId.includes('.') && attck.techniqueById?.[aliasId.split('.')[0]]) {
      return { id: aliasId.split('.')[0], resolvedFrom: id, inKb: true };
    }
  }
  return { id, resolvedFrom: null, inKb: false };
}

function normalizeType(t) {
  const TI_TYPE_RULES = getTiTypeRules();
  const TYPE_ALIASES = getTypeAliases();
  const s = String(t || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/-/g, '_');
  if (!s) return '';
  if (TI_TYPE_RULES[s]) return s;
  if (TYPE_ALIASES[s]) return TYPE_ALIASES[s];
  
  for (const [k, v] of Object.entries(TYPE_ALIASES)) {
    const key = String(k).toLowerCase();
    if (key.length < 3) continue;
    if (s === key) return v;
    if (key.length >= 4 && (s.includes(key) || key.includes(s))) return v;
    if (/[\u4e00-\u9fff]/.test(key) && key.length >= 2 && s.includes(key)) return v;
  }
  for (const key of Object.keys(TI_TYPE_RULES)) {
    if (key.length < 4) continue;
    if (s.includes(key) || key.includes(s)) return key;
  }
  return s;
}

function qualityOf(confidence) {
  const c = Number(confidence) || 0;
  return QUALITY_LEVELS.find((q) => c >= q.min) || QUALITY_LEVELS[QUALITY_LEVELS.length - 1];
}

function extractExplicitIds(text) {
  const ids = [];
  const re = /\b(T\d{4}(?:\.\d{3})?)\b/gi;
  let m;
  while ((m = re.exec(String(text || ''))) !== null) {
    ids.push(m[1].toUpperCase());
  }
  return [...new Set(ids)];
}

function enrichMapping(attck, partial) {
  const techId = partial.primary;
  const tech = attck.techniqueById?.[techId] || null;
  const parentId =
    partial.parentId ||
    tech?.parentId ||
    (techId && String(techId).includes('.') ? String(techId).split('.')[0] : '');
  const tacticId = partial.tacticId || tech?.tacticId || null;
  const tactic = (attck.tactics || []).find((t) => t.id === tacticId) || null;
  const q = qualityOf(partial.confidence);
  const techniqueName = tech?.name || partial.techniqueName || techId;
  const techniqueNameEn = tech?.nameEn || '';
  const sourceIds = [
    ...new Set(
      (Array.isArray(partial.sourceIds) ? partial.sourceIds : [])
        .map((x) => normalizeTechniqueId(x) || String(x || '').toUpperCase())
        .filter(Boolean)
    )
  ];
  const resolvedFrom =
    partial.resolvedFrom ||
    (sourceIds.length === 1 && sourceIds[0] !== techId ? sourceIds[0] : null);
  return {
    primary: techId,
    parentId: parentId || undefined,
    secondary: partial.secondary || [],
    confidence: partial.confidence,
    method: partial.method,
    methodLabel: METHOD_LABELS[partial.method] || partial.method,
    techniqueName,
    techniqueNameEn,
    
    displayName:
      techniqueName && techniqueName !== techId
        ? techniqueName
        : techniqueNameEn || techniqueName || techId,
    tacticId: tacticId || '',
    tacticName: tactic?.name || tech?.tacticName || '',
    tacticNameEn: tactic?.nameEn || tech?.tacticNameEn || '',
    killChainOrder: tactic?.order || tech?.order || 99,
    quality: q.level,
    qualityLabel: q.label,
    rationale: partial.rationale || '',
    sourceIds,
    resolvedFrom: resolvedFrom || undefined,
    inKb: Boolean(tech)
  };
}

function collapseParentChildTechniques(ids) {
  const set = new Set((ids || []).filter(Boolean));
  for (const id of [...set]) {
    if (String(id).includes('.')) {
      const parent = String(id).split('.')[0];
      if (set.has(parent)) set.delete(parent);
    }
  }
  return set;
}

function inferTypeFromIocs(iocs) {
  const types = new Set((iocs || []).map((i) => i.type));
  const cats = new Set((iocs || []).map((i) => i.category).filter(Boolean));
  if (types.has('url') || types.has('email') || cats.has('url') || cats.has('email')) return 'url-indicator';
  if (types.has('domain') || cats.has('domain')) return 'domain-indicator';
  if (types.has('ipv4') || types.has('ipv6') || cats.has('ip')) return 'ip-indicator';
  if (types.has('md5') || types.has('sha1') || types.has('sha256') || cats.has('malware')) return 'hash-indicator';
  if (types.has('cve') || cats.has('vulnerability')) return 'cve';
  return '';
}

function withIocColumns(row, iocs, iocSummary) {
  const kn = knowledge();
  const mapping = row.mapping;
  const techniqueMappings =
    Array.isArray(row.techniqueMappings) && row.techniqueMappings.length
      ? row.techniqueMappings
      : mapping
        ? [mapping]
        : [];
  return {
    ...row,
    mapping: mapping || techniqueMappings[0],
    techniqueMappings,
    techniqueCount: techniqueMappings.length,
    rawTechniqueIds: row.rawTechniqueIds || row.techniqueIds || [],
    iocs,
    iocSummary,
    iocColumns: groupIocsByColumns(iocs, kn.iocDisplayColumns, kn.iocTypeToColumn)
  };
}

function mapExplicitTechniqueList(attck, item, techIds, iocs, iocSummary) {
  const TECHNIQUE_TACTIC_HINT = getTechniqueTacticHints();
  const byPrimary = new Map();
  const rawTechniqueIds = [];
  for (const raw of techIds) {
    const norm = normalizeTechniqueId(raw);
    if (norm) rawTechniqueIds.push(norm);
    const resolved = resolveTechniqueId(attck, raw);
    if (!resolved) continue;
    const sourceId = norm || resolved.resolvedFrom || resolved.id;
    const existing = byPrimary.get(resolved.id);
    if (existing) {
      const srcs = new Set([...(existing.sourceIds || []), sourceId, resolved.id]);
      existing.sourceIds = [...srcs];
      byPrimary.set(resolved.id, enrichMapping(attck, { ...existing, sourceIds: existing.sourceIds }));
      continue;
    }
    let rationale = `技术编号 ${resolved.id} 已在 ATT&CK 知识库中匹配`;
    if (resolved.resolvedFrom) {
      rationale = `技术编号 ${resolved.resolvedFrom} 已对齐为 ${resolved.id}`;
    } else if (!resolved.inKb) {
      rationale = `技术编号 ${resolved.id} 暂未收录完整条目，已保留原编号`;
    }
    const partial = {
      primary: resolved.id,
      secondary: [],
      confidence: resolved.inKb ? 0.96 : 0.88,
      method: 'explicit',
      rationale,
      techniqueName: resolved.inKb ? undefined : resolved.id,
      sourceIds: [sourceId],
      resolvedFrom: resolved.resolvedFrom || (sourceId !== resolved.id ? sourceId : null)
    };
    const hint =
      item.explicitTacticId ||
      TECHNIQUE_TACTIC_HINT[resolved.id] ||
      TECHNIQUE_TACTIC_HINT[resolved.id.split('.')[0]];
    if (!attck.techniqueById?.[resolved.id]?.tacticId && hint) partial.tacticId = hint;
    byPrimary.set(resolved.id, enrichMapping(attck, partial));
  }
  const techniqueMappings = [...byPrimary.values()].sort(
    (a, b) =>
      (a.killChainOrder || 99) - (b.killChainOrder || 99) ||
      String(a.primary).localeCompare(String(b.primary))
  );
  if (!techniqueMappings.length) return null;
  return withIocColumns(
    {
      ...item,
      mapping: techniqueMappings[0],
      techniqueMappings,
      techniqueCount: techniqueMappings.length,
      rawTechniqueIds: [...new Set(rawTechniqueIds)],
      rawTechniqueCount: [...new Set(rawTechniqueIds)].length,
      tacticNames: [
        ...new Set(techniqueMappings.map((m) => m.tacticName).filter(Boolean))
      ]
    },
    iocs,
    iocSummary
  );
}

function mapOne(attck, item) {
  const TI_TYPE_RULES = getTiTypeRules();
  const TYPE_ALIASES = getTypeAliases();
  const TECHNIQUE_TACTIC_HINT = getTechniqueTacticHints();

  const textBlob = [
    item.title,
    item.description,
    item.threatType,
    ...(item.tags || []),
    typeof item.raw === 'string' ? item.raw : '',
    item.raw && typeof item.raw === 'object' ? item.raw.description || item.raw.text || '' : ''
  ]
    .filter(Boolean)
    .join('\n');
  const regexIocs = extractIocs(textBlob);
  const structured = (item.structuredIocs || item.iocs || []).map((x) => ({
    type: String(x.type || 'unknown').toLowerCase(),
    category: x.category ? String(x.category).toLowerCase() : undefined,
    value: String(x.value || ''),
    source: 'structured'
  }));
  const iocs = mergeIocs(structured, regexIocs);
  const iocSummary = summarizeIocs(iocs);

  
  let techIds = Array.isArray(item.techniqueIds)
    ? item.techniqueIds.map((x) => String(x).toUpperCase()).filter((x) => /^T\d{4}/.test(x))
    : [];
  if (!techIds.length && item.explicitTechniqueId) {
    let explicitRaw = String(item.explicitTechniqueId).toUpperCase();
    if (!/^T\d{4}/.test(explicitRaw)) {
      techIds = extractExplicitIds(String(item.explicitTechniqueId));
    } else {
      techIds = [explicitRaw];
    }
  }
  if (!techIds.length) {
    techIds = extractExplicitIds(textBlob);
  }
  techIds = [...new Set(techIds)];
  if (techIds.length) {
    const multi = mapExplicitTechniqueList(attck, item, techIds, iocs, iocSummary);
    if (multi) return multi;
  }

  
  let typeKey = normalizeType(item.threatType);
  if (!TI_TYPE_RULES[typeKey]) {
    const blob = textBlob.toLowerCase();
    for (const [alias, key] of Object.entries(TYPE_ALIASES)) {
      if (alias.length >= 2 && blob.includes(String(alias).toLowerCase()) && TI_TYPE_RULES[key]) {
        typeKey = key;
        break;
      }
    }
  }
  if (!typeKey || !TI_TYPE_RULES[typeKey]) {
    typeKey = normalizeType(inferTypeFromIocs(iocs));
  }
  if (!TI_TYPE_RULES[typeKey]) {
    for (const tag of item.tags || []) {
      const k = normalizeType(tag);
      if (TI_TYPE_RULES[k]) {
        typeKey = k;
        break;
      }
    }
  }
  if (TI_TYPE_RULES[typeKey]) {
    const rule = TI_TYPE_RULES[typeKey];
    return withIocColumns(
      {
        ...item,
        mapping: enrichMapping(attck, {
          primary: rule.primary,
          secondary: rule.secondary || [],
          confidence: rule.confidence,
          method: 'rule',
          rationale: `类型规则匹配: ${typeKey}`
        })
      },
      iocs,
      iocSummary
    );
  }

  
  const hit = findBestTechniqueHit(textBlob, attck);
  if (hit && hit.techId && (hit.confidence || 0) >= 0.55) {
    return withIocColumns(
      {
        ...item,
        mapping: enrichMapping(attck, {
          primary: hit.techId,
          secondary: hit.secondary || [],
          confidence: Math.min(0.92, Number(hit.confidence) || 0.75),
          method: 'heuristic',
          rationale: hit.source ? `词典/语料启发(${hit.source})` : '词典/关键词启发匹配'
        })
      },
      iocs,
      iocSummary
    );
  }

  
  const fbType = inferTypeFromIocs(iocs);
  if (fbType && TI_TYPE_RULES[fbType]) {
    const rule = TI_TYPE_RULES[fbType];
    return withIocColumns(
      {
        ...item,
        mapping: enrichMapping(attck, {
          primary: rule.primary,
          secondary: rule.secondary || [],
          confidence: Math.min(0.7, rule.confidence - 0.15),
          method: 'fallback',
          rationale: `依 IOC 类型回退: ${fbType}`
        })
      },
      iocs,
      iocSummary
    );
  }

  
  const fallbackId = getFallbackTechniqueId();
  return withIocColumns(
    {
      ...item,
      mapping: enrichMapping(attck, {
        primary: fallbackId,
        secondary: [],
        confidence: 0.55,
        method: 'fallback',
        rationale: '无强特征，回退至默认技术，建议复核或启用大模型辅助'
      })
    },
    iocs,
    iocSummary
  );
}

function mapBatch(attck, items) {
  return (items || []).map((it) => mapOne(attck, it));
}

function computeStats(mapped) {
  const list = mapped || [];
  const n = list.length;
  let confSum = 0;
  let llmCount = 0;
  const methodCount = {};
  const qualityCount = {};
  const tacticSet = new Set();
  const techniqueSet = new Set();
  const iocByType = {};
  const iocByColumn = {};
  const seenIoc = new Set();
  let iocTotal = 0;
  const kn = knowledge();
  const typeToCol = kn.iocTypeToColumn || {};

  for (const row of list) {
    const maps =
      Array.isArray(row.techniqueMappings) && row.techniqueMappings.length
        ? row.techniqueMappings
        : row.mapping
          ? [row.mapping]
          : [];
    for (const m of maps) {
      confSum += Number(m.confidence) || 0;
      methodCount[m.method] = (methodCount[m.method] || 0) + 1;
      qualityCount[m.quality] = (qualityCount[m.quality] || 0) + 1;
      if (m.method === 'llm' || m.method === 'vector') llmCount += 1;
      if (m.tacticId) tacticSet.add(m.tacticId);
      if (m.primary) techniqueSet.add(m.primary);
    }
    for (const ioc of row.iocs || []) {
      const key = `${ioc.category || ioc.type}|${ioc.value}`;
      if (seenIoc.has(key)) continue;
      seenIoc.add(key);
      iocTotal += 1;
      iocByType[ioc.type] = (iocByType[ioc.type] || 0) + 1;
      const col = ioc.category || typeToCol[ioc.type] || ioc.type;
      iocByColumn[col] = (iocByColumn[col] || 0) + 1;
    }
  }

  const mapHits = list.reduce((acc, row) => {
    const maps =
      Array.isArray(row.techniqueMappings) && row.techniqueMappings.length
        ? row.techniqueMappings
        : row.mapping
          ? [row.mapping]
          : [];
    return acc + maps.length;
  }, 0);
  const avgConf = mapHits ? confSum / mapHits : 0;
  const good = list.filter((r) => {
    const maps =
      Array.isArray(r.techniqueMappings) && r.techniqueMappings.length
        ? r.techniqueMappings
        : r.mapping
          ? [r.mapping]
          : [];
    return maps.some((m) => (m.confidence || 0) >= 0.8);
  }).length;
  const tacticDenom = (list[0] && list.length) ? 14 : 14;
  return {
    mappedCount: n,
    avgConfidence: Number(avgConf.toFixed(4)),
    accuracyPercent: n ? Number(((good / n) * 100).toFixed(1)) : 0,
    tacticCoverageCount: tacticSet.size,
    tacticCoveragePercent: Number(((tacticSet.size / tacticDenom) * 100).toFixed(1)),
    techniqueCount: techniqueSet.size,
    methodCount,
    qualityCount,
    llmAssistedCount: llmCount,
    iocTotal,
    iocByType,
    iocByColumn
  };
}

function buildCoverage(attck, mapped) {
  const counts = {};
  for (const t of attck.tactics || []) {
    counts[t.id] = { ...t, count: 0, techniques: {}, techniqueList: [] };
  }

  
  const placed = new Map(); 
  for (const row of mapped || []) {
    const maps =
      Array.isArray(row.techniqueMappings) && row.techniqueMappings.length
        ? row.techniqueMappings
        : row.mapping
          ? [row.mapping]
          : [];
    for (const m of maps) {
      const tid = m?.primary;
      if (!tid || !m.tacticId || !counts[m.tacticId]) continue;
      const prev = placed.get(tid);
      if (prev) {
        prev.count += 1;
        if (Array.isArray(m.sourceIds)) {
          prev.sourceIds = [...new Set([...(prev.sourceIds || []), ...m.sourceIds])];
        }
        continue;
      }
      placed.set(tid, {
        id: tid,
        name: m.displayName || m.techniqueName || tid,
        nameEn: m.techniqueNameEn || '',
        tacticId: m.tacticId,
        count: 1,
        sourceIds: Array.isArray(m.sourceIds) ? [...m.sourceIds] : [],
        parentId: m.parentId || (String(tid).includes('.') ? String(tid).split('.')[0] : '')
      });
    }
  }

  
  const keepIds = collapseParentChildTechniques([...placed.keys()]);
  for (const [tid, meta] of placed) {
    if (!keepIds.has(tid)) continue;
    const bucket = counts[meta.tacticId];
    if (!bucket) continue;
    bucket.count += meta.count;
    bucket.techniques[tid] = meta.count;
    bucket.techniqueList.push({
      id: tid,
      name: meta.name,
      nameEn: meta.nameEn,
      count: meta.count,
      sourceIds: meta.sourceIds
    });
  }

  return (attck.killChainOrder || attck.tactics || []).map((t) => {
    const bucket = counts[t.id] || { ...t, count: 0, techniques: {}, techniqueList: [] };
    bucket.techniqueList = (bucket.techniqueList || []).sort((a, b) =>
      String(a.id).localeCompare(String(b.id))
    );
    return bucket;
  });
}

module.exports = {
  QUALITY_LEVELS,
  METHOD_LABELS,
  get TI_TYPE_RULES() {
    return getTiTypeRules();
  },
  get TECHNIQUE_ALIASES() {
    return getTechniqueAliases();
  },
  mapOne,
  mapBatch,
  computeStats,
  buildCoverage,
  enrichMapping,
  normalizeType,
  resolveTechniqueId,
  collapseParentChildTechniques,
  getTiTypeRules,
  getTechniqueAliases,
  getFallbackTechniqueId
};
