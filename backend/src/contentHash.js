const crypto = require('crypto');

function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
    .join(',')}}`;
}

function sha256(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

function hashIntelsInput(intels) {
  const norm = (intels || []).map((a) => ({
    id: a.id || null,
    timestamp: a.timestamp || a.time || null,
    threatType: a.threatType || a.type || null,
    title: a.title || a.name || null,
    description: a.description || a.desc || a.text || a.message || null,
    text: a.text || null
  }));
  return sha256(stableStringify(norm));
}

function hashAlertsInput(alerts) {
  return hashIntelsInput(alerts);
}

function hashMappedIntels(mapped) {
  const norm = (mapped || []).map((m) => itemPayloadMapped(m));
  return sha256(stableStringify(norm));
}

function hashMappedAlerts(mapped) {
  return hashMappedIntels(mapped);
}

function itemPayloadMapped(m) {
  return {
    id: m.id || null,
    timestamp: m.timestamp || null,
    threatType: m.threatType || m.attackType || null,
    title: m.title || null,
    description: m.description || null,
    technique: m.mapping?.primary || m.techniqueId || null,
    tactic: m.mapping?.tacticId || null
  };
}

function itemHashMappedIntel(m) {
  return sha256(stableStringify(itemPayloadMapped(m)));
}

function itemHashMappedAlert(m) {
  return itemHashMappedIntel(m);
}

function itemPayloadChain(c) {
  return {
    name: c.name || null,
    intelCount: c.intelCount || c.alertCount || 0,
    techniques: [...(c.techniques || [])].sort(),
    coveredTactics: [...(c.coveredTactics || [])].sort(),
    timeline: (c.timeline || []).map((t) => ({
      title: t.title || null,
      technique: t.technique || null,
      techniques: t.techniques || null
    }))
  };
}

function hashChains(chains) {
  const norm = (chains || []).map((c) => itemPayloadChain(c));
  return sha256(stableStringify(norm));
}

function itemHashChain(c) {
  return sha256(stableStringify(itemPayloadChain(c)));
}

function classifyPersistKind(total, existedCount) {
  if (!total) return 'all_new';
  if (existedCount <= 0) return 'all_new';
  if (existedCount >= total) return 'all_exist';
  return 'partial';
}

function majorityBatchId(existingDocs, fallback) {
  const counts = new Map();
  for (const d of existingDocs || []) {
    if (!d || !d.batchId) continue;
    counts.set(d.batchId, (counts.get(d.batchId) || 0) + 1);
  }
  let best = fallback;
  let bestN = 0;
  for (const [id, n] of counts) {
    if (n > bestN) {
      best = id;
      bestN = n;
    }
  }
  return best || fallback;
}

function resolvePersistBatchId(persistKind, sessionBatchId, existingDocs, newBatchId) {
  if (persistKind === 'all_exist') {
    return majorityBatchId(existingDocs, sessionBatchId);
  }
  return newBatchId || sessionBatchId;
}

function userPersistMessage(mode, persistKind, { total = 0, existed = 0, added = 0 } = {}) {
  if (persistKind === 'all_exist') {
    if (mode === 'intels' || mode === 'alerts') {
      return `这 ${total} 条映射结果已在库中（与已有数据相同或为其子集），未重复保存。`;
    }
    if (mode === 'chains') {
      return `该批次的攻击链路已在库中，未重复保存。`;
    }
    return `该批次的统计与覆盖数据已在库中，未重复保存。`;
  }
  if (persistKind === 'partial') {
    if (mode === 'intels' || mode === 'alerts') {
      return `已保存本批 ${total} 条映射结果（新增 ${added} 条；另有 ${existed} 条与库中已有内容相同）。`;
    }
    if (mode === 'chains') {
      return `已保存本批 ${total} 条攻击链路。`;
    }
    return `已保存本批统计与覆盖数据。`;
  }
  if (mode === 'intels' || mode === 'alerts') return `已新保存 ${total} 条映射结果。`;
  if (mode === 'chains') return `已新保存 ${total} 条攻击链路。`;
  return `已新保存统计与覆盖数据。`;
}

function userPersistTitle(persistKind) {
  if (persistKind === 'all_exist') return '已存在，无需重复入库';
  if (persistKind === 'partial') return '保存成功';
  return '保存成功';
}

module.exports = {
  stableStringify,
  sha256,
  hashIntelsInput,
  hashAlertsInput,
  hashMappedIntels,
  hashMappedAlerts,
  hashChains,
  itemHashMappedIntel,
  itemHashMappedAlert,
  itemHashChain,
  classifyPersistKind,
  majorityBatchId,
  resolvePersistBatchId,
  userPersistMessage,
  userPersistTitle
};
