const fs = require('fs');
const path = require('path');

const KILL_CHAIN_ORDER = [
  { id: 'TA0043', name: '侦察', nameEn: 'Reconnaissance', order: 1 },
  { id: 'TA0042', name: '资源开发', nameEn: 'Resource Development', order: 2 },
  { id: 'TA0001', name: '初始访问', nameEn: 'Initial Access', order: 3 },
  { id: 'TA0002', name: '执行', nameEn: 'Execution', order: 4 },
  { id: 'TA0003', name: '持久化', nameEn: 'Persistence', order: 5 },
  { id: 'TA0004', name: '权限提升', nameEn: 'Privilege Escalation', order: 6 },
  { id: 'TA0005', name: '防御规避', nameEn: 'Defense Evasion', order: 7 },
  { id: 'TA0006', name: '凭证访问', nameEn: 'Credential Access', order: 8 },
  { id: 'TA0007', name: '发现', nameEn: 'Discovery', order: 9 },
  { id: 'TA0008', name: '横向移动', nameEn: 'Lateral Movement', order: 10 },
  { id: 'TA0009', name: '数据收集', nameEn: 'Collection', order: 11 },
  { id: 'TA0011', name: '命令与控制', nameEn: 'Command and Control', order: 12 },
  { id: 'TA0010', name: '渗出', nameEn: 'Exfiltration', order: 13 },
  { id: 'TA0040', name: '影响', nameEn: 'Impact', order: 14 }
];

function extractKeywords(name) {
  const terms = [];
  const cn = String(name || '').replace(/[（(].*?[）)]/g, '').trim();
  if (cn) terms.push(cn.toLowerCase());
  const en = String(name || '').match(/[A-Za-z][A-Za-z0-9\s/-]+/);
  if (en) {
    en[0]
      .toLowerCase()
      .split(/[\s/-]+/)
      .filter((w) => w.length > 2)
      .forEach((w) => terms.push(w));
  }
  return [...new Set(terms)];
}

function parseTechniqueBlock(text, tacticId) {
  const techniques = [];
  const parts = text.split(/(?=[①②③④⑤⑥⑦⑧⑨⑩⑪⑫]|[0-9]+[、．.]\s*攻击主技术)/);

  for (const part of parts) {
    if (!part || part.trim().length < 10) continue;
    const techMatch = part.match(/攻击主技术的编号[：:]\s*(T\d{4}(?:\.\d{3})?)/);
    const nameMatch = part.match(/攻击主技术的名称[：:]\s*([^，,（(]+)/);
    if (!techMatch) continue;

    const techniqueId = techMatch[1];
    const techniqueName = nameMatch ? nameMatch[1].trim() : techniqueId;
    const subTechniques = [];
    const subRegex = /(T\d{4}\.\d{3})\s*[（(]([^）)]+)[）)]/g;
    let m;
    while ((m = subRegex.exec(part)) !== null) {
      subTechniques.push({ id: m[1], name: m[2].trim() });
    }

    techniques.push({
      id: techniqueId,
      name: techniqueName,
      nameEn: '',
      tacticId,
      tacticIds: [tacticId],
      subTechniques,
      source: 'legacy-narrative'
    });
  }
  return techniques;
}

function loadFromEnterpriseFile(jsonPath) {
  const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const tactics = Array.isArray(data.tactics) && data.tactics.length ? data.tactics : [...KILL_CHAIN_ORDER];
  const techniqueById = data.techniqueById || {};
  const techniques = Array.isArray(data.techniques)
    ? data.techniques
    : Object.values(techniqueById).filter((t) => t && !String(t.id).includes('.'));

  
  for (const t of techniques) {
    if (!techniqueById[t.id]) techniqueById[t.id] = t;
    for (const sub of t.subTechniques || []) {
      if (!techniqueById[sub.id]) {
        techniqueById[sub.id] = {
          id: sub.id,
          name: sub.name || sub.id,
          nameEn: sub.nameEn || '',
          tacticId: t.tacticId,
          tacticIds: t.tacticIds || [t.tacticId],
          parentId: t.id,
          subTechniques: [],
          source: t.source || 'mitre-attack'
        };
      }
    }
  }

  const keywords = [];
  for (const t of Object.values(techniqueById)) {
    if (!t?.id || String(t.id).includes('.')) continue;
    keywords.push({
      techniqueId: t.id,
      tacticId: t.tacticId,
      terms: extractKeywords(t.name || t.nameEn || '')
    });
  }

  return {
    tactics,
    techniques,
    techniqueById,
    keywords,
    killChainOrder: data.killChainOrder || tactics,
    meta: data._meta || { source: jsonPath }
  };
}

function loadFromLegacyNarrative(jsonPath) {
  const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const tactics = [...KILL_CHAIN_ORDER];
  const techniques = [];
  const techniqueById = {};
  const keywords = [];

  for (const item of raw) {
    const title = item.title || '';
    const text = item.text || '';
    let tacticId = null;
    const m1 = title.match(/TA\d{4}/);
    const m2 = title.match(/攻击战术编号为\s*(TA\d{4})/);
    if (m2) tacticId = m2[1];
    else if (m1 && /包含的攻击技术|攻击战术编号为/.test(title)) tacticId = m1[0];

    if (tacticId && text.includes('攻击主技术')) {
      const techs = parseTechniqueBlock(text, tacticId);
      for (const t of techs) {
        techniques.push(t);
        techniqueById[t.id] = t;
        for (const sub of t.subTechniques) {
          techniqueById[sub.id] = {
            id: sub.id,
            name: sub.name,
            tacticId,
            tacticIds: [tacticId],
            parentId: t.id,
            subTechniques: [],
            source: 'legacy-narrative'
          };
        }
        keywords.push({
          techniqueId: t.id,
          tacticId,
          terms: extractKeywords(t.name)
        });
      }
    }
  }

  return {
    tactics,
    techniques,
    techniqueById,
    keywords,
    killChainOrder: KILL_CHAIN_ORDER,
    meta: { source: 'legacy-ATTCK.json' }
  };
}

function candidateEnterprisePaths() {
  return [
    path.join(__dirname, '../../data/attck_enterprise.json'),
    path.join(__dirname, '../data/attck_enterprise.json'),
    path.join(process.cwd(), 'data/attck_enterprise.json'),
    path.join(process.cwd(), '../data/attck_enterprise.json')
  ];
}

function candidateLegacyPaths() {
  return [
    path.join(__dirname, '../../data/ATTCK.json'),
    path.join(__dirname, '../data/ATTCK.json'),
    '/home/www/backend/data/ATTCK.json',
    '/home/www/data/ATTCK.json',
    path.join(process.cwd(), 'data/ATTCK.json'),
    path.join(process.cwd(), '../data/ATTCK.json')
  ];
}

function getDefaultAttckPath() {
  for (const p of candidateEnterprisePaths()) {
    if (fs.existsSync(p)) return p;
  }
  for (const p of candidateLegacyPaths()) {
    if (fs.existsSync(p)) return p;
  }
  return candidateLegacyPaths()[0];
}

function loadAttckData(jsonPath) {
  const filePath = jsonPath || getDefaultAttckPath();
  if (!filePath || !fs.existsSync(filePath)) {
    console.warn('[ATT&CK] 未找到知识库文件，返回空库');
    return {
      tactics: [...KILL_CHAIN_ORDER],
      techniques: [],
      techniqueById: {},
      keywords: [],
      killChainOrder: KILL_CHAIN_ORDER,
      meta: { source: 'empty' }
    };
  }

  const base = path.basename(filePath).toLowerCase();
  let data;
  if (base.includes('enterprise') || base === 'attck_enterprise.json') {
    data = loadFromEnterpriseFile(filePath);
  } else {
    
    const ent = candidateEnterprisePaths().find((p) => fs.existsSync(p));
    if (ent) {
      data = loadFromEnterpriseFile(ent);
      console.log(
        `[ATT&CK] ${Object.keys(data.techniqueById).length} techniques ← ${ent}`
      );
      return data;
    }
    data = loadFromLegacyNarrative(filePath);
  }

  console.log(
    `[ATT&CK] ${data.techniques.length} tactics-tech, ${Object.keys(data.techniqueById).length} ids ← ${filePath}`
  );
  return data;
}

module.exports = {
  KILL_CHAIN_ORDER,
  loadAttckData,
  getDefaultAttckPath,
  extractKeywords
};
