const config = require('./config');
const { enrichMapping, resolveTechniqueId } = require('./tiMapper');

let corpusCache = null;

function shouldAssist(row) {
  const m = row?.mapping || {};
  const conf = Number(m.confidence) || 0;
  return m.method === 'fallback' || m.method === 'heuristic' || conf < 0.75;
}

async function embedTexts(texts) {
  if (!config.vectorReady) {
    throw new Error('向量服务未配置（VECTOR_API_KEY / VECTOR_BASE_URL / VECTOR_MODEL）');
  }
  const url = `${config.vector.baseUrl}/embeddings`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.vector.apiKey}`
    },
    body: JSON.stringify({
      model: config.vector.model,
      input: texts,
      encoding_format: 'float'
    })
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Vector HTTP ${res.status}: ${errText.slice(0, 300)}`);
  }
  const data = await res.json();
  const rows = data.data || [];
  rows.sort((a, b) => (a.index || 0) - (b.index || 0));
  return rows.map((r) => r.embedding || []);
}

function cosine(a, b) {
  if (!a?.length || !b?.length || a.length !== b.length) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

function buildTechniqueCorpus(attck) {
  const list = [];
  const seen = new Set();
  for (const t of attck.techniques || []) {
    const id = t.id || t.techniqueId;
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const name = t.name || t.nameZh || t.nameEn || id;
    const nameEn = t.nameEn || '';
    const tactics = (t.tacticIds || (t.tacticId ? [t.tacticId] : [])).join(' ');
    list.push({
      id,
      text: `${id} ${name} ${nameEn} ${tactics}`.slice(0, 400)
    });
  }
  
  return list.slice(0, 400);
}

async function ensureCorpus(attck) {
  if (corpusCache?.attckRef === attck && corpusCache.vectors?.length) return corpusCache;
  const items = buildTechniqueCorpus(attck);
  if (!items.length) {
    corpusCache = { attckRef: attck, items: [], vectors: [] };
    return corpusCache;
  }
  const vectors = await embedTexts(items.map((x) => x.text));
  corpusCache = { attckRef: attck, items, vectors };
  return corpusCache;
}

async function assistWithVector(attck, mapped, opts = {}) {
  const maxItems = opts.maxItems || 6;
  const errors = [];
  if (!config.vectorReady) {
    return { mapped, vectorCount: 0, errors: [{ stage: 'vector', error: 'vector not configured' }] };
  }

  const candidates = (mapped || [])
    .map((row, idx) => ({ row, idx }))
    .filter((x) => shouldAssist(x.row))
    .slice(0, maxItems);

  if (!candidates.length) return { mapped, vectorCount: 0, errors };

  let corpus;
  try {
    corpus = await ensureCorpus(attck);
  } catch (e) {
    return { mapped, vectorCount: 0, errors: [{ stage: 'vector-corpus', error: e.message }] };
  }
  if (!corpus.items.length) return { mapped, vectorCount: 0, errors };

  const out = mapped.slice();
  let vectorCount = 0;

  for (const { row, idx } of candidates) {
    try {
      const blob = `${row.title || ''}\n${row.description || ''}`.slice(0, 1500);
      const [qVec] = await embedTexts([blob]);
      let best = null;
      for (let i = 0; i < corpus.items.length; i++) {
        const score = cosine(qVec, corpus.vectors[i]);
        if (!best || score > best.score) {
          best = { id: corpus.items[i].id, score };
        }
      }
      if (!best || best.score < 0.42) continue;
      const resolved = resolveTechniqueId(attck, best.id);
      if (!resolved) continue;
      const mapping = enrichMapping(attck, {
        primary: resolved.id,
        secondary: row.mapping?.primary && row.mapping.primary !== resolved.id ? [row.mapping.primary] : [],
        confidence: Math.min(0.9, 0.55 + best.score * 0.4),
        method: 'vector',
        rationale: `向量相似命中 ${resolved.id}（score=${best.score.toFixed(3)}）`
      });
      out[idx] = {
        ...row,
        mapping,
        techniqueMappings: [mapping],
        techniqueCount: 1,
        vectorAssisted: true
      };
      vectorCount += 1;
    } catch (e) {
      errors.push({ stage: 'vector-item', index: idx, error: e.message });
    }
  }

  return { mapped: out, vectorCount, errors };
}

module.exports = {
  assistWithVector,
  embedTexts,
  cosine
};
