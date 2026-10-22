const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

const DEFAULT_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-16.1.json';

const ROOT = path.resolve(__dirname, '../..');
const OUT_ENTERPRISE = path.join(ROOT, 'data', 'attck_enterprise.json');
const OUT_ALIASES = path.join(ROOT, 'data', 'attck_official_aliases.json');
const LEGACY_ATTCK = path.join(ROOT, 'data', 'ATTCK.json');

const TACTIC_SHORTNAME_TO_ID = {
  reconnaissance: 'TA0043',
  'resource-development': 'TA0042',
  'initial-access': 'TA0001',
  execution: 'TA0002',
  persistence: 'TA0003',
  'privilege-escalation': 'TA0004',
  'defense-evasion': 'TA0005',
  'credential-access': 'TA0006',
  discovery: 'TA0007',
  'lateral-movement': 'TA0008',
  collection: 'TA0009',
  'command-and-control': 'TA0011',
  exfiltration: 'TA0010',
  impact: 'TA0040'
};

const TACTIC_META = [
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

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { headers: { 'User-Agent': 'QY-ThreatIntel-attck-builder' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        fetchUrl(res.headers.location).then(resolve, reject);
        res.resume();
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        res.resume();
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject);
  });
}

function loadLegacyChineseNames() {
  const map = {};
  if (!fs.existsSync(LEGACY_ATTCK)) return map;
  try {
    const raw = JSON.parse(fs.readFileSync(LEGACY_ATTCK, 'utf8'));
    for (const item of raw) {
      const text = String(item.text || '');
      const re =
        /攻击主技术的名称[：:]\s*([^，,（(]+?)[（(]?([^）)]*)[）)]?[^，,]*攻击主技术的编号[：:]\s*(T\d{4}(?:\.\d{3})?)/g;
      let m;
      while ((m = re.exec(text)) !== null) {
        const cn = m[1].trim();
        const enInParen = (m[2] || '').trim();
        const id = m[3].toUpperCase();
        if (cn) map[id] = enInParen ? `${cn}（${enInParen}）` : cn;
      }
      const subRe = /(T\d{4}\.\d{3})\s*[（(]([^）)]+)[）)]/g;
      while ((m = subRe.exec(text)) !== null) {
        const id = m[1].toUpperCase();
        if (!map[id]) map[id] = m[2].trim();
      }
    }
  } catch (e) {
    console.warn('[warn] legacy Chinese names skipped:', e.message);
  }
  return map;
}

function attackIdOf(obj) {
  const ext = (obj.external_references || []).find(
    (r) => r.source_name === 'mitre-attack' && /^T\d{4}/.test(String(r.external_id || ''))
  );
  return ext ? String(ext.external_id).toUpperCase() : null;
}

function tacticIdsOf(obj) {
  const ids = [];
  for (const p of obj.kill_chain_phases || []) {
    if (p.kill_chain_name !== 'mitre-attack') continue;
    const tid = TACTIC_SHORTNAME_TO_ID[p.phase_name];
    if (tid) ids.push(tid);
  }
  return [...new Set(ids)];
}

function buildFromBundle(bundle, sourceUrl) {
  const objects = bundle.objects || [];
  const byStixId = new Map(objects.map((o) => [o.id, o]));
  const cnNames = loadLegacyChineseNames();

  const techniques = [];
  const techniqueById = {};
  const officialAliases = {};
  const revokedPairs = [];

  for (const obj of objects) {
    if (obj.type !== 'attack-pattern') continue;
    if (obj.x_mitre_is_subtechnique) continue; 

    const id = attackIdOf(obj);
    if (!id || !/^T\d{4}$/.test(id)) continue;
    if (obj.revoked) continue;

    const tactics = tacticIdsOf(obj);
    const nameEn = obj.name || id;
    const name = cnNames[id] || `${nameEn}`;
    const entry = {
      id,
      name,
      nameEn,
      tacticId: tactics[0] || null,
      tacticIds: tactics,
      description: String(obj.description || '')
        .replace(/\n+/g, ' ')
        .slice(0, 500),
      subTechniques: [],
      deprecated: Boolean(obj.x_mitre_deprecated),
      source: 'mitre-attack'
    };
    techniques.push(entry);
    techniqueById[id] = entry;
  }

  
  for (const obj of objects) {
    if (obj.type !== 'attack-pattern') continue;
    if (!obj.x_mitre_is_subtechnique) continue;
    const id = attackIdOf(obj);
    if (!id || !/^T\d{4}\.\d{3}$/.test(id)) continue;
    if (obj.revoked) continue;

    const parentId = id.split('.')[0];
    const tactics = tacticIdsOf(obj);
    const nameEn = obj.name || id;
    const name = cnNames[id] || nameEn;
    const sub = {
      id,
      name,
      nameEn,
      tacticId: tactics[0] || techniqueById[parentId]?.tacticId || null,
      tacticIds: tactics.length ? tactics : techniqueById[parentId]?.tacticIds || [],
      parentId,
      subTechniques: [],
      deprecated: Boolean(obj.x_mitre_deprecated),
      source: 'mitre-attack'
    };
    techniqueById[id] = sub;
    if (techniqueById[parentId]) {
      techniqueById[parentId].subTechniques.push({ id, name, nameEn });
    }
  }

  
  for (const obj of objects) {
    if (obj.type !== 'attack-pattern') continue;
    const oldId = attackIdOf(obj);
    if (!oldId) continue;

    
    const oldIds = obj.x_mitre_old_attack_id;
    if (oldIds) {
      const list = Array.isArray(oldIds) ? oldIds : [oldIds];
      for (const o of list) {
        const from = String(o).toUpperCase();
        if (/^T\d{4}/.test(from) && from !== oldId) {
          officialAliases[from] = oldId;
          revokedPairs.push({ from, to: oldId, reason: 'x_mitre_old_attack_id' });
        }
      }
    }
  }

  for (const rel of objects) {
    if (rel.type !== 'relationship' || rel.relationship_type !== 'revoked-by') continue;
    const source = byStixId.get(rel.source_ref);
    const target = byStixId.get(rel.target_ref);
    if (!source || !target) continue;
    const from = attackIdOf(source);
    const to = attackIdOf(target);
    if (from && to && from !== to) {
      officialAliases[from] = to;
      revokedPairs.push({ from, to, reason: 'revoked-by' });
    }
  }

  
  
  const WELL_KNOWN = {
    T1086: 'T1059.001', 
    T1193: 'T1566.001', 
    T1064: 'T1059', 
    T1107: 'T1070', 
    T1060: 'T1547.001', 
    T1085: 'T1218.011', 
    T1045: 'T1027', 
    T1077: 'T1021.002', 
    T1035: 'T1569.002' 
  };

  const enterprise = {
    _meta: {
      source: 'MITRE ATT&CK Enterprise (STIX)',
      sourceUrl,
      builtAt: new Date().toISOString(),
      techniqueCount: Object.keys(techniqueById).filter((k) => !k.includes('.')).length,
      subtechniqueCount: Object.keys(techniqueById).filter((k) => k.includes('.')).length,
      aliasCount: Object.keys(officialAliases).length
    },
    tactics: TACTIC_META,
    killChainOrder: TACTIC_META,
    techniques: techniques.sort((a, b) => a.id.localeCompare(b.id)),
    techniqueById
  };

  const aliasesDoc = {
    _comment:
      '仅包含 ATT&CK 官方废止/更名映射。禁止把语义不同的现行技术互相折叠（如 T1001/T1090/T1102 ≠ T1071）。',
    sourceUrl,
    builtAt: new Date().toISOString(),
    techniqueAliases: officialAliases,
    pairs: revokedPairs
  };

  return { enterprise, aliasesDoc };
}

async function main() {
  const args = process.argv.slice(2);
  let url = DEFAULT_URL;
  let localFile = null;
  const i = args.indexOf('--url');
  if (i >= 0 && args[i + 1]) url = args[i + 1];
  const j = args.indexOf('--file');
  if (j >= 0 && args[j + 1]) localFile = args[j + 1];

  let buf;
  let sourceLabel = url;
  if (localFile) {
    const abs = path.resolve(localFile);
    console.log('[build] reading local', abs);
    buf = fs.readFileSync(abs);
    sourceLabel = abs;
  } else {
    console.log('[build] downloading', url);
    buf = await fetchUrl(url);
  }
  console.log('[build] source bytes', buf.length);
  const bundle = JSON.parse(buf.toString('utf8'));
  const { enterprise, aliasesDoc } = buildFromBundle(bundle, sourceLabel);

  fs.mkdirSync(path.dirname(OUT_ENTERPRISE), { recursive: true });
  fs.writeFileSync(OUT_ENTERPRISE, JSON.stringify(enterprise, null, 2), 'utf8');
  fs.writeFileSync(OUT_ALIASES, JSON.stringify(aliasesDoc, null, 2), 'utf8');

  console.log('[build] wrote', OUT_ENTERPRISE);
  console.log(
    '[build] techniques',
    enterprise._meta.techniqueCount,
    'subtechniques',
    enterprise._meta.subtechniqueCount
  );
  console.log('[build] wrote', OUT_ALIASES, 'aliases', Object.keys(aliasesDoc.techniqueAliases).length);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
