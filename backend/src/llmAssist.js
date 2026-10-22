const config = require('./config');
const { enrichMapping, resolveTechniqueId, getFallbackTechniqueId } = require('./tiMapper');
const { mergeIocs, pickRepresentativeIocs } = require('./iocExtract');

function pickMessageText(msg) {
  const content = String(msg?.content || '').trim();
  if (content) return content;

  const reasoning = String(msg?.reasoning_content || '').trim();
  if (!reasoning) return '';

  
  const markers = [/^##\s+总体威胁研判/m, /^##\s+\S+/m, /总体威胁研判/];
  for (const re of markers) {
    const m = reasoning.match(re);
    if (m && m.index != null) {
      const sliced = reasoning.slice(m.index).trim();
      if (sliced.length >= 40) return sliced.startsWith('##') ? sliced : `## ${sliced}`;
    }
  }
  return reasoning;
}

async function chatCompletion(llm, messages, opts = {}) {
  if (!llm.apiKey || !llm.baseUrl || !llm.model) {
    throw new Error('LLM 未配置（请检查 .env 中的 API Key / Base URL / Model）');
  }
  const url = `${llm.baseUrl}/chat/completions`;
  const maxTokens = opts.max_tokens ?? 1200;
  const body = {
    model: llm.model,
    messages,
    temperature: opts.temperature ?? 0.2,
    
    max_tokens: maxTokens
  };
  let res;
  let lastErr;
  
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${llm.apiKey}`
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(180_000)
      });
      lastErr = null;
      break;
    } catch (e) {
      lastErr = e;
      const msg = e.cause?.message || e.message || String(e);
      if (attempt < 2) {
        await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
        continue;
      }
      throw new Error(`LLM 请求失败: ${msg}`);
    }
  }
  if (lastErr) throw lastErr;
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`LLM HTTP ${res.status}: ${errText.slice(0, 300)}`);
  }
  const data = await res.json();
  const msg = data.choices?.[0]?.message || {};
  let content = pickMessageText(msg);

  
  const usage = data.usage || {};
  const reasoningTokens = usage.completion_tokens_details?.reasoning_tokens;
  const hitReasoningCap =
    !String(msg.content || '').trim() &&
    reasoningTokens != null &&
    Number(usage.completion_tokens || 0) >= maxTokens * 0.9;

  if ((!content || content.length < 40) && hitReasoningCap && !opts._retried) {
    return chatCompletion(llm, messages, {
      ...opts,
      max_tokens: Math.min(Math.max(maxTokens * 2, 8192), 16384),
      _retried: true
    });
  }

  return content;
}

function cleanLlmAnalysis(text) {
  let s = String(text || '')
    .replace(/\u0000/g, '')
    .replace(/\r\n/g, '\n')
    .trim();
  if (!s) return null;

  const h2 = s.search(/^##\s+总体威胁研判/m);
  const h2Any = h2 >= 0 ? h2 : s.search(/^##\s+\S/m);
  if (h2Any > 0) {
    const before = s.slice(0, h2Any);
    const looksLikeCot =
      /we need|let'?s |i will|i need|the user|structured markdown|chinese chars|directly give|do not repeat|output headings|我们需要|用户要求|不要思考过程/i.test(
        before
      ) ||
      (before.length > 120 && !/^##\s+/m.test(before));
    if (looksLikeCot) s = s.slice(h2Any).trim();
  }

  if (!/^##\s+/m.test(s)) {
    const zh = s.search(/总体威胁研判/);
    if (zh >= 0) s = `## ${s.slice(zh).trim()}`;
  }

  const zhCount = (s.match(/[\u4e00-\u9fff]/g) || []).length;
  if (zhCount < 24 || s.length < 40) return null;
  
  if (!/^##\s+/m.test(s) && !/总体威胁研判|处置建议|狩猎/.test(s)) return null;
  return s;
}

function extractJsonBlock(text) {
  const raw = String(text || '').trim();
  const fence = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fence ? fence[1].trim() : raw;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try {
      return JSON.parse(candidate.slice(start, end + 1));
    } catch (_) {
      
    }
  }
  try {
    return JSON.parse(candidate);
  } catch (_) {
    return null;
  }
}

async function assistMapItem(attck, item, opts = {}) {
  const text = [item.title, item.description].filter(Boolean).join('\n').slice(0, 3500);
  const current = item.mapping || {};
  const prompt = `你是威胁情报与 MITRE ATT&CK 专家。根据情报文本，输出严格 JSON（不要 markdown）：
{
  "techniqueId": "Txxxx 或 Txxxx.xxx",
  "secondary": ["Txxxx"],
  "confidence": 0.0-1.0,
  "rationale": "一句话中文理由",
  "iocs": [{"type":"ipv4|domain|url|md5|sha1|sha256|email|cve|filepath","value":"..."}]
}
要求：techniqueId 必须是合法 ATT&CK 技术编号；若无法判断可沿用当前映射 ${current.primary || 'T1071'}。
当前规则映射: ${current.primary || '-'} (${current.method || '-'}, conf=${current.confidence || '-'})
情报文本:
${text}`;

  const content = await chatCompletion(
    config.openieLlm,
    [
      { role: 'system', content: '只输出 JSON，不要解释。' },
      { role: 'user', content: prompt }
    ],
    { temperature: 0.1, max_tokens: 800 }
  );
  const parsed = extractJsonBlock(content);
  if (!parsed) {
    return { ...item, llmError: '无法解析大模型输出', llmRaw: content.slice(0, 500) };
  }

  const fallbackId = getFallbackTechniqueId();
  let techId = String(parsed.techniqueId || current.primary || fallbackId).toUpperCase();
  if (!/^T\d{4}/.test(techId)) techId = current.primary || fallbackId;
  const resolved = resolveTechniqueId(attck, techId);
  if (resolved?.inKb) {
    techId = resolved.id;
  } else if (!attck.techniqueById?.[techId] && !attck.techniqueById?.[techId.split('.')[0]]) {
    techId = current.primary || fallbackId;
  } else if (!attck.techniqueById?.[techId] && attck.techniqueById?.[techId.split('.')[0]]) {
    techId = techId.split('.')[0];
  }

  const conf = Math.max(
    Number(current.confidence) || 0,
    Math.min(0.96, Number(parsed.confidence) || 0.8)
  );
  const llmIocs = Array.isArray(parsed.iocs)
    ? parsed.iocs
        .filter((x) => x && x.value)
        .map((x) => ({
          type: String(x.type || 'unknown').toLowerCase(),
          value: String(x.value),
          source: 'llm'
        }))
    : [];

  const mapping = enrichMapping(attck, {
    primary: techId,
    secondary: Array.isArray(parsed.secondary) ? parsed.secondary.slice(0, 3) : current.secondary || [],
    confidence: conf,
    method: 'llm',
    rationale: parsed.rationale || '大模型辅助映射'
  });

  return {
    ...item,
    iocs: mergeIocs(item.iocs || [], llmIocs),
    mapping,
    llmAssisted: true
  };
}

async function assistMapBatch(attck, mapped, opts = {}) {
  const maxItems = Math.min(opts.maxItems || 8, mapped.length);
  const needAssist = mapped
    .map((row, idx) => ({ row, idx }))
    .filter(({ row }) => {
      const m = row.mapping || {};
      return m.method === 'fallback' || m.quality === 'poor' || (m.confidence || 0) < 0.75;
    })
    .slice(0, maxItems);

  const out = mapped.slice();
  const errors = [];
  for (const { row, idx } of needAssist) {
    try {
      out[idx] = await assistMapItem(attck, row, opts);
    } catch (e) {
      errors.push({ index: idx, error: e.message });
    }
  }
  return { mapped: out, assistedCount: needAssist.length, errors };
}

function buildCampaignBrief(mapped, opts = {}) {
  const list = mapped || [];
  const techMap = new Map(); 
  const tacticMap = new Map();
  const methods = {};
  let confSum = 0;
  let confN = 0;
  const iocTypeCount = {};
  const allIocs = [];

  for (const r of list) {
    const maps =
      Array.isArray(r.techniqueMappings) && r.techniqueMappings.length
        ? r.techniqueMappings
        : r.mapping
          ? [r.mapping]
          : [];
    for (const m of maps) {
      const id = m.primary;
      if (!id) continue;
      const prev = techMap.get(id) || {
        id,
        name: m.techniqueName || m.displayName || id,
        tacticId: m.tacticId || '',
        tacticName: m.tacticName || '',
        order: m.killChainOrder || 99,
        confidenceMax: 0,
        methods: {},
        count: 0
      };
      prev.count += 1;
      prev.confidenceMax = Math.max(prev.confidenceMax, Number(m.confidence) || 0);
      const meth = m.method || 'unknown';
      prev.methods[meth] = (prev.methods[meth] || 0) + 1;
      methods[meth] = (methods[meth] || 0) + 1;
      confSum += Number(m.confidence) || 0;
      confN += 1;
      techMap.set(id, prev);

      if (m.tacticId) {
        const t = tacticMap.get(m.tacticId) || {
          id: m.tacticId,
          name: m.tacticName || m.tacticId,
          order: m.killChainOrder || 99,
          techniques: new Set()
        };
        t.techniques.add(id);
        tacticMap.set(m.tacticId, t);
      }
    }

    for (const ioc of r.iocs || []) {
      if (!ioc?.value) continue;
      const typ = String(ioc.category || ioc.type || 'other').toLowerCase();
      iocTypeCount[typ] = (iocTypeCount[typ] || 0) + 1;
      allIocs.push(ioc);
    }
  }

  const techniques = [...techMap.values()]
    .sort(
      (a, b) =>
        (a.order || 99) - (b.order || 99) ||
        b.confidenceMax - a.confidenceMax ||
        String(a.id).localeCompare(String(b.id))
    )
    .slice(0, 48)
    .map((t) => ({
      id: t.id,
      name: t.name,
      tacticId: t.tacticId,
      tacticName: t.tacticName,
      confidence: Number(t.confidenceMax.toFixed(2)),
      hits: t.count
    }));

  const killChain = [...tacticMap.values()]
    .sort((a, b) => (a.order || 99) - (b.order || 99))
    .map((t) => ({
      tacticId: t.id,
      tacticName: t.name,
      techniqueIds: [...t.techniques].sort()
    }));

  
  const mergedRow = {
    iocs: allIocs,
    iocColumns: {},
    iocSummary: iocTypeCount
  };
  const iocSample = pickRepresentativeIocs(mergedRow, opts.iocSample);

  const itemSummaries = list.slice(0, 10).map((r, i) => {
    const maps =
      Array.isArray(r.techniqueMappings) && r.techniqueMappings.length
        ? r.techniqueMappings
        : r.mapping
          ? [r.mapping]
          : [];
    return {
      i: i + 1,
      title: String(r.title || '').slice(0, 100),
      type: r.threatType || '',
      source: r.source || '',
      sourceId: r.sourceId || r.rid || '',
      techniqueCount: maps.length,
      topTechniques: maps.slice(0, 8).map((m) => m.primary).filter(Boolean),
      primaryConfidence: r.mapping?.confidence ?? null,
      method: r.mapping?.method || '',
      iocCount: (r.iocs || []).length
    };
  });

  return {
    overview: {
      itemCount: list.length,
      uniqueTechniques: techMap.size,
      uniqueTactics: tacticMap.size,
      avgConfidence: confN ? Number((confSum / confN).toFixed(3)) : 0,
      methodDistribution: methods,
      iocTotal: allIocs.length,
      iocByType: iocTypeCount
    },
    killChain,
    techniques,
    iocSamples: iocSample.byType,
    iocSampleMeta: {
      available: iocSample.meta.available,
      sampled: iocSample.meta.sampled,
      truncated: iocSample.meta.truncated
    },
    items: itemSummaries
  };
}

async function analyzeIntel(mapped, opts = {}) {
  const brief = buildCampaignBrief(mapped, opts);

  const prompt = `你是资深威胁情报分析师。下面 JSON 是本批情报经规则映射后的「战役简报」（已去重技战术、含杀伤链与代表性 IOC），请据此输出中文 Markdown 研判。
要求：
1. 直接写正文，禁止思考过程、英文草稿、字数规划或「我需要…」等元叙述
2. 面向安全运营/分析人员，800 字以内；不要复述 JSON 原文，不要罗列全部 IOC
3. 优先依据 killChain / techniques（含 confidence）判断攻击阶段与能力；结合 overview.methodDistribution 评估映射可靠度
4. IOC 建议必须引用 iocSamples 中的具体值（可点名少量高价值域名/IP/哈希/路径），禁止编造未见过的指标
5. 结构请严格按下列标题：
## 总体威胁研判
（2-4 句：攻击者意图、初始入口、主要目标）
## 关键 ATT&CK 战术与技术（按杀伤链阶段顺序）
对每个相关战术用：#### 战术名（TAxxxx）
下列技术：- **Txxxx** 名称（可注明高置信）
## 关键 IOC 与狩猎建议
结合 iocByType 与 iocSamples 给出可执行狩猎/封禁建议
## 风险优先级与处置建议
简短列表（含优先级）
战役简报JSON:
${JSON.stringify(brief, null, 2)}`;

  const content = await chatCompletion(
    config.chatLlm,
    [
      {
        role: 'system',
        content: '只输出中文 Markdown 分析正文，从「## 总体威胁研判」起笔，不要思考过程，不要英文。'
      },
      { role: 'user', content: prompt }
    ],
    
    { temperature: 0.2, max_tokens: opts.max_tokens || 8192 }
  );

  const cleaned = cleanLlmAnalysis(content);
  if (!cleaned) {
    return {
      analysis:
        content && String(content).length >= 40
          ? String(content)
          : '大模型未返回有效分析内容，请稍后重试或关闭大模型辅助以查看规则摘要。',
      model: config.chatLlm.model,
      sampleSize: brief.overview.itemCount,
      warning: 'empty_or_invalid',
      valid: false
    };
  }

  return {
    analysis: cleaned,
    model: config.chatLlm.model,
    sampleSize: brief.overview.itemCount,
    briefMeta: {
      uniqueTechniques: brief.overview.uniqueTechniques,
      uniqueTactics: brief.overview.uniqueTactics,
      iocSampled: brief.iocSampleMeta?.sampled
    },
    valid: true
  };
}

module.exports = {
  assistMapItem,
  assistMapBatch,
  analyzeIntel,
  buildCampaignBrief,
  chatCompletion,
  extractJsonBlock,
  cleanLlmAnalysis
};
