const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');

const config = require('./config');
const { parseThreatIntelText } = require('./tiParse');
const { mapBatch, computeStats, buildCoverage, getTiTypeRules, METHOD_LABELS } = require('./tiMapper');
const { assistMapBatch, analyzeIntel } = require('./llmAssist');
const { assistWithVector } = require('./vectorAssist');
const { MappedIntel, SessionStats, SampleIntel } = require('./models');
const { summarizeIocs } = require('./iocExtract');
const { getMappingKnowledge } = require('./knowledgeLoader');
const { parseBodyInputAsync } = require('./fileText');
const {
  itemHashMappedIntel,
  hashMappedIntels,
  classifyPersistKind,
  userPersistMessage,
  userPersistTitle
} = require('./contentHash');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

function isMongoReady() {
  return mongoose.connection.readyState === 1;
}

function itemHash(item) {
  return itemHashMappedIntel(item).slice(0, 32);
}

function pickSourceId(row) {
  const cand = row?.sourceId ?? row?.rid ?? row?.id;
  if (cand == null || cand === '') return undefined;
  return String(cand);
}

function toPersistDoc(row, batchId) {
  const sourceId = pickSourceId(row);
  const hash = row.itemHash || itemHash(row);
  return {
    batchId,
    ...(sourceId ? { sourceId } : {}),
    itemHash: hash,
    contentHash: row.contentHash || hashMappedIntels([row]),
    title: row.title,
    description: row.description,
    threatType: row.threatType,
    tags: Array.isArray(row.tags) ? row.tags : [],
    source: row.source,
    timestamp: row.timestamp,
    iocs: row.iocs,
    iocSummary: row.iocSummary,
    iocColumns: row.iocColumns,
    mapping: row.mapping,
    techniqueMappings: row.techniqueMappings,
    techniqueIds: row.techniqueIds || row.rawTechniqueIds,
    rawTechniqueIds: row.rawTechniqueIds,
    techniqueCount: row.techniqueCount,
    llmAssisted: row.llmAssisted,
    vectorAssisted: row.vectorAssisted,
    analysisSnippet:
      typeof row.analysisSnippet === 'string'
        ? row.analysisSnippet
        : undefined,
    raw: row.raw && typeof row.raw === 'object'
      ? (() => {
          const { _id, id, ...rest } = row.raw;
          return rest;
        })()
      : row.raw
  };
}

function truthy(v) {
  return v === true || v === 'true' || v === '1' || v === 1;
}

function createRouter(attck) {
  const router = express.Router();

  router.get('/health', (req, res) => {
    res.json({
      ok: true,
      name: '威胁情报映射分析系统',
      mongo: isMongoReady(),
      tactics: attck.tactics?.length || 0,
      techniques: attck.techniques?.length || 0,
      llmReady: config.llmReady,
      vectorReady: config.vectorReady,
      models: {
        openie: config.openieLlm.model,
        chat: config.chatLlm.model,
        vector: config.vector.model
      }
    });
  });

  router.get('/attck/tactics', (req, res) => {
    res.json({
      killChainOrder: attck.killChainOrder || attck.tactics,
      tactics: attck.tactics,
      techniques: attck.techniques
    });
  });

  router.get('/mapping/rules', (req, res) => {
    const kn = getMappingKnowledge();
    res.json({
      rules: getTiTypeRules(),
      methodLabels: METHOD_LABELS,
      iocDisplayColumns: kn.iocDisplayColumns,
      iocTypeToColumn: kn.iocTypeToColumn,
      techniqueAliasCount: Object.keys(kn.techniqueAliases || {}).length
    });
  });

  async function runMappingPipeline(text, { llmMapEnabled, llmAnalyzeEnabled, wantAnalysis }) {
    const items = parseThreatIntelText(text);
    if (!items.length) {
      const err = new Error('未能解析出情报条目，请检查格式');
      err.status = 400;
      throw err;
    }
    const batchId = uuidv4().slice(0, 8);
    let mapped = mapBatch(attck, items).map((row) => ({
      ...row,
      batchId,
      itemHash: itemHash(row)
    }));

    let llmMeta = { assistedCount: 0, vectorCount: 0, errors: [] };
    if (llmMapEnabled) {
      try {
        const vr = await assistWithVector(attck, mapped, { maxItems: 6 });
        mapped = vr.mapped;
        llmMeta.vectorCount = vr.vectorCount || 0;
        if (vr.errors?.length) llmMeta.errors.push(...vr.errors);
      } catch (e) {
        llmMeta.errors.push({ stage: 'vector', error: e.message });
      }
      try {
        const lr = await assistMapBatch(attck, mapped, { maxItems: 8 });
        mapped = lr.mapped;
        llmMeta.assistedCount = lr.assistedCount || 0;
        if (lr.errors?.length) llmMeta.errors.push(...lr.errors);
      } catch (e) {
        llmMeta.errors.push({ stage: 'llm-map', error: e.message });
      }
    }

    mapped = mapped.map((row) => ({
      ...row,
      iocSummary: summarizeIocs(row.iocs || [])
    }));

    let analysis = null;
    if (wantAnalysis) {
      if (llmAnalyzeEnabled) {
        try {
          analysis = await analyzeIntel(mapped);
        } catch (e) {
          analysis = { analysis: `分析失败：${e.message}`, error: e.message };
        }
      } else {
        analysis = wrapRuleAnalysis(mapped);
      }
    }

    const stats = computeStats(mapped);
    const coveragePack = normalizeCoverage(buildCoverage(attck, mapped));
    return {
      batchId,
      items: mapped,
      mapped,
      stats,
      coverage: coveragePack.matrix,
      coverageMeta: {
        orphanTechniques: coveragePack.orphanTechniques,
        techniquePlacedCount: coveragePack.techniquePlacedCount
      },
      analysis,
      llmMeta,
      llmMapEnabled: Boolean(llmMapEnabled),
      llmAnalyzeEnabled: Boolean(llmAnalyzeEnabled),
      
      llmEnabled: Boolean(llmMapEnabled || llmAnalyzeEnabled)
    };
  }

  function normalizeCoverage(coverageResult) {
    if (Array.isArray(coverageResult)) {
      return { matrix: coverageResult, orphanTechniques: [], techniquePlacedCount: null };
    }
    return {
      matrix: coverageResult?.matrix || [],
      orphanTechniques: coverageResult?.orphanTechniques || [],
      techniquePlacedCount: coverageResult?.techniquePlacedCount ?? null
    };
  }

  function buildRuleBasedAnalysis(mapped) {
    const stats = computeStats(mapped);
    const order = attck.killChainOrder || attck.tactics || [];
    const orderIndex = new Map(order.map((t, i) => [t.id, t.order != null ? t.order : i + 1]));
    const byTactic = new Map();

    for (const r of mapped) {
      const maps =
        Array.isArray(r.techniqueMappings) && r.techniqueMappings.length
          ? r.techniqueMappings
          : r.mapping
            ? [r.mapping]
            : [];
      for (const m of maps) {
        const tacticId = m.tacticId || 'UNKNOWN';
        const tacticName = m.tacticName || (tacticId !== 'UNKNOWN' ? tacticId : '未归类');
        const techId = m.primary || '';
        if (!techId) continue;
        if (!byTactic.has(tacticId)) {
          byTactic.set(tacticId, {
            id: tacticId,
            name: tacticName,
            order: orderIndex.has(tacticId)
              ? orderIndex.get(tacticId)
              : m.killChainOrder || 99,
            techniques: new Map()
          });
        }
        const bucket = byTactic.get(tacticId);
        if (!bucket.techniques.has(techId)) {
          bucket.techniques.set(techId, {
            id: techId,
            name: m.techniqueName || techId,
            nameEn: m.techniqueNameEn || ''
          });
        }
      }
    }

    const tactics = [...byTactic.values()]
      .sort((a, b) => (a.order || 99) - (b.order || 99) || String(a.id).localeCompare(String(b.id)))
      .map((tac) => {
        const techniques = [...tac.techniques.values()].sort((a, b) =>
          String(a.id).localeCompare(String(b.id))
        );
        return {
          id: tac.id,
          name: tac.name,
          order: tac.order,
          techniques
        };
      });

    const iocEntries = Object.entries(stats.iocByColumn || stats.iocByType || {}).filter(
      ([, v]) => Number(v) > 0
    );
    iocEntries.sort((a, b) => b[1] - a[1]);
    const iocSummary = iocEntries.length
      ? iocEntries.map(([k, v]) => `${k} ${v}`).join(' · ')
      : '无';

    const techNote =
      stats.rawTechniqueCount && stats.rawTechniqueCount !== stats.techniqueCount
        ? `（报告列出 ${stats.rawTechniqueCount} 项）`
        : '';

    const summary = `共映射 ${stats.mappedCount} 条情报。命中技术 ${stats.techniqueCount} 项${techNote}，覆盖战术 ${stats.tacticCoverageCount}/${stats.tacticTotal}（${stats.tacticCoveragePercent}%）。平均置信度 ${(stats.avgConfidence * 100).toFixed(1)}%。`;

    const sections = {
      title: '规则引擎分析摘要',
      summary,
      tactics,
      iocSummary,
      footer: '启用「大模型辅助分析」后，将生成更深入的战役研判。'
    };

    
    const tacticBlocks = tactics.map((tac) => {
      const techLines = tac.techniques
        .map((t) =>
          t.name && t.name !== t.id ? `- **${t.id}** ${t.name}` : `- **${t.id}**`
        )
        .join('\n');
      const title =
        tac.id && tac.id !== 'UNKNOWN'
          ? `#### ${tac.name}（${tac.id}）· ${tac.techniques.length} 项技术`
          : `#### ${tac.name} · ${tac.techniques.length} 项技术`;
      return `${title}\n${techLines}`;
    });

    const text = [
      `## ${sections.title}`,
      '',
      summary,
      '',
      '### 主要技战术战术分布（MITRE ATT&CK）',
      '',
      tacticBlocks.length ? tacticBlocks.join('\n\n') : '- 无命中战术',
      '',
      '### IOC 统计',
      '',
      iocSummary,
      '',
      `> ${sections.footer}`
    ].join('\n');

    return { text, sections };
  }

  function wrapRuleAnalysis(mapped) {
    const pack = buildRuleBasedAnalysis(mapped);
    return {
      analysis: pack.text,
      sections: pack.sections,
      model: 'rule-engine',
      sampleSize: mapped.length
    };
  }

  router.post('/mapping/batch', upload.single('file'), async (req, res) => {
    try {
      const text = await parseBodyInputAsync(req);
      const llmMapEnabled = truthy(req.body?.llmMapEnabled ?? req.body?.llmEnabled);
      const result = await runMappingPipeline(text, {
        llmMapEnabled,
        llmAnalyzeEnabled: false,
        wantAnalysis: false
      });
      res.json(result);
    } catch (e) {
      res.status(e.status || 500).json({ error: e.message });
    }
  });

  router.post('/analyze', upload.single('file'), async (req, res) => {
    try {
      const llmMapEnabled = truthy(req.body?.llmMapEnabled ?? req.body?.llmEnabled);
      const llmAnalyzeEnabled = truthy(req.body?.llmAnalyzeEnabled ?? req.body?.llmEnabled);
      let mapped = null;
      let batchId = req.body?.batchId || uuidv4().slice(0, 8);

      if (req.body?.mapped) {
        mapped =
          typeof req.body.mapped === 'string' ? JSON.parse(req.body.mapped) : req.body.mapped;
      }
      if (!Array.isArray(mapped) || !mapped.length) {
        const text = await parseBodyInputAsync(req);
        if (!String(text || '').trim()) {
          return res.status(400).json({ error: '请先完成映射，或提供情报后再分析' });
        }
        const result = await runMappingPipeline(text, {
          llmMapEnabled,
          llmAnalyzeEnabled,
          wantAnalysis: true
        });
        return res.json(result);
      }

      let analysis;
      try {
        if (llmAnalyzeEnabled) {
          analysis = await analyzeIntel(mapped);
        } else {
          analysis = wrapRuleAnalysis(mapped);
        }
      } catch (e) {
        analysis = {
          analysis: `分析失败：${e.message}`,
          error: e.message,
          model: llmAnalyzeEnabled ? 'llm' : 'rule-engine'
        };
      }

      const stats = computeStats(mapped);
      const coveragePack = normalizeCoverage(buildCoverage(attck, mapped));
      res.json({
        batchId,
        mapped,
        stats,
        coverage: coveragePack.matrix,
        coverageMeta: {
          orphanTechniques: coveragePack.orphanTechniques,
          techniquePlacedCount: coveragePack.techniquePlacedCount
        },
        analysis,
        llmMapEnabled,
        llmAnalyzeEnabled,
        llmEnabled: Boolean(llmMapEnabled || llmAnalyzeEnabled)
      });
    } catch (e) {
      res.status(e.status || 500).json({ error: e.message });
    }
  });

  router.post('/pipeline', upload.single('file'), async (req, res) => {
    try {
      const text = await parseBodyInputAsync(req);
      const llmMapEnabled = truthy(req.body?.llmMapEnabled ?? req.body?.llmEnabled);
      const llmAnalyzeEnabled = truthy(req.body?.llmAnalyzeEnabled ?? req.body?.llmEnabled);
      const result = await runMappingPipeline(text, {
        llmMapEnabled,
        llmAnalyzeEnabled,
        wantAnalysis: true
      });
      res.json(result);
    } catch (e) {
      res.status(e.status || 500).json({ error: e.message });
    }
  });

  router.post('/persist', async (req, res) => {
    try {
      if (!isMongoReady()) {
        return res.status(503).json({ error: 'MongoDB 未连接，无法入库' });
      }
      const mode = req.body?.mode || 'intels';
      const batchId = req.body?.batchId || uuidv4().slice(0, 8);
      if (mode === 'intels') {
        const mapped = req.body?.mapped || [];
        if (!mapped.length) return res.status(400).json({ error: '没有可入库的映射结果' });

        const docs = mapped.map((row) => toPersistDoc(row, batchId));
        const hashes = docs.map((d) => d.itemHash).filter(Boolean);
        const existing = hashes.length
          ? await MappedIntel.find({ itemHash: { $in: hashes } }).select('itemHash').lean()
          : [];
        const existedSet = new Set(existing.map((d) => d.itemHash));
        const toInsert = docs.filter((d) => !existedSet.has(d.itemHash));
        const persistKind = classifyPersistKind(docs.length, existedSet.size);

        if (toInsert.length) {
          await MappedIntel.insertMany(toInsert);
        }

        return res.json({
          ok: true,
          title: userPersistTitle(persistKind),
          message: userPersistMessage('intels', persistKind, {
            total: docs.length,
            existed: existedSet.size,
            added: toInsert.length
          }),
          count: toInsert.length,
          existed: existedSet.size,
          batchId,
          persistKind
        });
      }
      if (mode === 'stats') {
        await SessionStats.findOneAndUpdate(
          { batchId },
          {
            batchId,
            stats: req.body?.stats || {},
            coverage: req.body?.coverage || [],
            analysis: req.body?.analysis || '',
            llmEnabled: Boolean(req.body?.llmEnabled)
          },
          { upsert: true, new: true }
        );
        return res.json({ ok: true, title: '统计已入库', batchId });
      }
      return res.status(400).json({ error: `未知 mode: ${mode}` });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.get('/stats/cumulative', async (req, res) => {
    try {
      if (!isMongoReady()) {
        return res.json({ mappedIntelCount: 0, iocTotal: 0 });
      }
      const mappedIntelCount = await MappedIntel.countDocuments({});
      const docs = await MappedIntel.find({}).select('iocSummary').lean();
      let iocTotal = 0;
      for (const d of docs) iocTotal += d.iocSummary?.total || 0;
      res.json({ mappedIntelCount, iocTotal });
    } catch (e) {
      res.json({ mappedIntelCount: 0, iocTotal: 0 });
    }
  });

  router.get('/samples', async (req, res) => {
    try {
      if (!isMongoReady()) {
        return res.json({ samples: builtinSamples() });
      }
      const list = await SampleIntel.find({}).select('sampleKey name description format').lean();
      res.json({ samples: list.length ? list : builtinSamples() });
    } catch (e) {
      res.json({ samples: builtinSamples() });
    }
  });

  router.get('/samples/:id', async (req, res) => {
    const id = req.params.id;
    const builtins = builtinSamples();
    const hit = builtins.find((s) => s.sampleKey === id || s._id === id);
    if (hit) return res.json(hit);
    if (!isMongoReady()) return res.status(404).json({ error: 'not found' });
    const doc =
      (await SampleIntel.findOne({ sampleKey: id }).lean()) ||
      (await SampleIntel.findById(id).lean().catch(() => null));
    if (!doc) return res.status(404).json({ error: 'not found' });
    res.json(doc);
  });

  return router;
}

function builtinSamples() {
  return [
    {
      _id: 'sample-stix',
      sampleKey: 'sample-stix',
      name: 'STIX 指标样例',
      description: '含 indicator + malware 的 STIX bundle',
      format: 'stix-json',
      content: JSON.stringify(
        {
          type: 'bundle',
          id: 'bundle--demo',
          objects: [
            {
              type: 'indicator',
              id: 'indicator--1',
              name: 'Malicious C2 domain',
              pattern: "[domain-name:value = 'evil-c2.example.com']",
              description: 'Command and control domain used by phishing dropper',
              labels: ['malicious-activity'],
              external_references: [{ source_name: 'mitre-attack', external_id: 'T1071' }]
            },
            {
              type: 'malware',
              id: 'malware--1',
              name: 'DemoStealer',
              description: 'Info stealer harvesting browser credentials and exfiltrating via HTTPS',
              labels: ['info-stealer']
            }
          ]
        },
        null,
        2
      )
    },
    {
      _id: 'sample-ioc-csv',
      sampleKey: 'sample-ioc-csv',
      name: 'IOC CSV 样例',
      description: 'type,value,title 格式',
      format: 'csv',
      content: [
        'type,value,title,description',
        'ipv4,203.0.113.88,可疑C2,对外扫描后回连',
        'domain,update-cdn-security.net,伪装更新域名,钓鱼邮件链接落地页',
        'sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,空文件哈希,测试占位',
        'cve,CVE-2024-21762,Fortinet漏洞,边界设备利用'
      ].join('\n')
    },
    {
      _id: 'sample-narrative',
      sampleKey: 'sample-narrative',
      name: '叙述型情报',
      description: '中文 APT 叙述',
      format: 'text',
      content: [
        '某APT组织通过钓鱼邮件投递木马，用户打开宏文档后执行PowerShell下载器。',
        '随后在主机落地远控木马，哈希 MD5: 44d88612fea8a8f36de82e1278abb02f，回连域名 apt-login-safe.com 与 IP 198.51.100.23。',
        '攻击者使用 Mimikatz 抓取凭证并经 RDP 横向移动，最终通过 DNS 隧道渗出数据。',
        '相关技术涉及 T1566、T1059、T1003、T1021。'
      ].join('\n')
    }
  ];
}

module.exports = { createRouter };
