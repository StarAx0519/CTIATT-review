const fs = require('fs');
const path = require('path');

const EMPTY = {
  fallbackTechniqueId: 'T1071',
  techniqueAliases: {},
  techniqueTacticHints: {},
  tiTypeRules: {},
  typeAliases: {},
  iocDisplayColumns: [
    { key: 'malware', label: 'malware' },
    { key: 'domain', label: 'domain' },
    { key: 'ip', label: 'ip' },
    { key: 'url', label: 'url' },
    { key: 'vulnerability', label: 'vulnerability' },
    { key: 'registry', label: 'registry' },
    { key: 'filepath', label: 'filepath' },
    { key: 'filename', label: 'filename' },
    { key: 'email', label: 'email' }
  ],
  iocTypeToColumn: {
    malware: 'malware',
    hash: 'malware',
    md5: 'malware',
    sha1: 'malware',
    sha256: 'malware',
    domain: 'domain',
    ip: 'ip',
    ipv4: 'ip',
    ipv6: 'ip',
    url: 'url',
    vulnerability: 'vulnerability',
    cve: 'vulnerability',
    registry: 'registry',
    filepath: 'filepath',
    filename: 'filename',
    email: 'email'
  }
};

let cached = null;
let cachedPath = null;

function candidatePaths() {
  const fromEnv = process.env.MAPPING_KNOWLEDGE_PATH;
  return [
    fromEnv,
    path.join(__dirname, '../../data/mapping_knowledge.json'),
    path.join(__dirname, '../data/mapping_knowledge.json'),
    path.join(process.cwd(), 'data/mapping_knowledge.json'),
    path.join(process.cwd(), '../data/mapping_knowledge.json')
  ].filter(Boolean);
}

function getDefaultKnowledgePath() {
  return candidatePaths().find((p) => fs.existsSync(p)) || null;
}

function candidateOfficialAliasPaths() {
  return [
    path.join(__dirname, '../../data/attck_official_aliases.json'),
    path.join(__dirname, '../data/attck_official_aliases.json'),
    path.join(process.cwd(), 'data/attck_official_aliases.json'),
    path.join(process.cwd(), '../data/attck_official_aliases.json')
  ];
}

function loadOfficialAliases() {
  const p = candidateOfficialAliasPaths().find((x) => fs.existsSync(x));
  if (!p) return {};
  try {
    const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
    return doc.techniqueAliases || {};
  } catch (_) {
    return {};
  }
}

function loadMappingKnowledge(jsonPath) {
  const filePath = jsonPath || getDefaultKnowledgePath();
  const official = loadOfficialAliases();
  if (!filePath || !fs.existsSync(filePath)) {
    console.warn('[Knowledge] mapping_knowledge.json 未找到，仅使用官方别名（若有）');
    cached = {
      ...EMPTY,
      techniqueAliases: { ...official },
      techniqueTacticHints: {},
      tiTypeRules: {},
      typeAliases: {}
    };
    cachedPath = null;
    return cached;
  }
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  cached = {
    fallbackTechniqueId: raw.fallbackTechniqueId || EMPTY.fallbackTechniqueId,
    techniqueAliases: { ...official, ...(raw.techniqueAliases || {}) },
    techniqueTacticHints: raw.techniqueTacticHints || {},
    tiTypeRules: raw.tiTypeRules || {},
    typeAliases: raw.typeAliases || {},
    iocDisplayColumns: Array.isArray(raw.iocDisplayColumns) && raw.iocDisplayColumns.length
      ? raw.iocDisplayColumns
      : EMPTY.iocDisplayColumns,
    iocTypeToColumn: { ...EMPTY.iocTypeToColumn, ...(raw.iocTypeToColumn || {}) }
  };
  cachedPath = filePath;
  console.log(
    `[Knowledge] loaded aliases=${Object.keys(cached.techniqueAliases).length} (official+local) typeRules=${Object.keys(cached.tiTypeRules).length} ← ${filePath}`
  );
  return cached;
}

function getMappingKnowledge() {
  if (!cached) return loadMappingKnowledge();
  return cached;
}

function getKnowledgePath() {
  return cachedPath;
}

module.exports = {
  loadMappingKnowledge,
  getMappingKnowledge,
  getDefaultKnowledgePath,
  getKnowledgePath,
  EMPTY_KNOWLEDGE: EMPTY
};
