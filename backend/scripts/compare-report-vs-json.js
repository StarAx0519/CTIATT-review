const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '../..');
const REPORT_DIR = path.join(ROOT, 'CTI/REPORT');
const JSON_DIR = path.join(ROOT, 'CTI/JSON');
const OUT = path.join(ROOT, 'docs/report-vs-json-compare.json');

require('../src/config');
const { loadMappingKnowledge } = require('../src/knowledgeLoader');
const { loadAttckData, getDefaultAttckPath } = require('../src/attckParser');
const { parseThreatIntelText } = require('../src/tiParse');
const { mapBatch } = require('../src/tiMapper');
const { extractFileText } = require('../src/fileText');
const { undefangText } = require('../src/iocExtract');

function arg(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (!hit) return fallback;
  return hit.slice(name.length + 3);
}

function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

function normIocValue(v) {
  return String(v || '')
    .trim()
    .toLowerCase()
    .replace(/\/+$/, '');
}

function iocKey(ioc) {
  const cat = String(ioc.category || ioc.type || 'unknown').toLowerCase();
  const type = String(ioc.type || cat).toLowerCase();
  const val = normIocValue(ioc.value);
  
  const looksPath =
    /^[a-z]:\\/.test(val) ||
    val.startsWith('%') ||
    val.includes('\\') ||
    val.startsWith('/tmp/') ||
    val.startsWith('/var/') ||
    val.startsWith('/etc/');
  const looksEmail = val.includes('@') && !val.includes('://');
  const looksHash = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(val);
  const bucket =
    cat === 'ip' || type === 'ipv4' || type === 'ipv6'
      ? 'ip'
      : looksHash ||
          cat === 'malware' ||
          type === 'md5' ||
          type === 'sha1' ||
          type === 'sha256' ||
          type === 'hash'
        ? 'malware'
        : looksEmail || type === 'email' || cat === 'email'
          ? 'email'
          : looksPath || type === 'filepath' || cat === 'filepath'
            ? 'filepath'
            : type === 'filename' || cat === 'filename'
              ? 'filename'
              : cat || type;
  
  return `${bucket}|${val.replace(/\//g, '\\')}`;
}

function techKey(id) {
  const s = String(id || '').toUpperCase();
  const m = s.match(/^(T\d{4}(?:\.\d{3})?)/);
  return m ? m[1] : '';
}

function collectFromMapped(mapped) {
  const iocs = new Set();
  const techs = new Set();
  const methods = {};
  let confSum = 0;
  let confN = 0;
  let tacticSet = new Set();
  for (const row of mapped || []) {
    for (const ioc of row.iocs || []) {
      if (ioc?.value) iocs.add(iocKey(ioc));
    }
    for (const t of row.tacticNames || []) tacticSet.add(String(t));
    const maps =
      Array.isArray(row.techniqueMappings) && row.techniqueMappings.length
        ? row.techniqueMappings
        : row.mapping
          ? [row.mapping]
          : [];
    for (const m of maps) {
      const id = techKey(m.primary);
      if (id) techs.add(id);
      const method = String(m.method || row.mapping?.method || 'unknown').toLowerCase();
      methods[method] = (methods[method] || 0) + 1;
      if (m.confidence != null) {
        confSum += Number(m.confidence) || 0;
        confN += 1;
      }
    }
    for (const raw of row.rawTechniqueIds || row.techniqueIds || []) {
      const id = techKey(raw);
      if (id) techs.add(id);
    }
  }
  return {
    iocs,
    techs,
    methods,
    avgConf: confN ? confSum / confN : 0,
    tacticCount: tacticSet.size
  };
}

function valueInText(value, textLower) {
  const v = normIocValue(value);
  if (!v || v.length < 3) return false;
  if (textLower.includes(v)) return true;
  
  const defanged = v.replace(/\./g, '[.]');
  if (textLower.includes(defanged)) return true;
  return false;
}

function recall(goldSet, predSet) {
  if (!goldSet.size) return 1;
  let hit = 0;
  for (const g of goldSet) if (predSet.has(g)) hit += 1;
  return hit / goldSet.size;
}

function listReportPairs() {
  const reports = fs.readdirSync(REPORT_DIR).filter((f) => /^Report_\d+\./i.test(f));
  const pairs = [];
  for (const file of reports) {
    const m = file.match(/^Report_(\d+)\.(\w+)$/i);
    if (!m) continue;
    const id = m[1];
    const ext = `.${m[2].toLowerCase()}`;
    const jsonPath = path.join(JSON_DIR, `Report_${id}.json`);
    if (!fs.existsSync(jsonPath)) continue;
    pairs.push({
      id,
      file,
      ext,
      reportPath: path.join(REPORT_DIR, file),
      jsonPath
    });
  }
  
  const byExt = new Map();
  for (const p of pairs) {
    if (!byExt.has(p.ext)) byExt.set(p.ext, []);
    byExt.get(p.ext).push(p);
  }
  for (const list of byExt.values()) {
    list.sort((a, b) => Number(a.id) - Number(b.id));
  }
  const exts = [...byExt.keys()].sort();
  const interleaved = [];
  let i = 0;
  for (;;) {
    let added = false;
    for (const ext of exts) {
      const list = byExt.get(ext);
      if (i < list.length) {
        interleaved.push(list[i]);
        added = true;
      }
    }
    if (!added) break;
    i += 1;
  }
  return interleaved;
}

async function mapText(attck, text) {
  const items = parseThreatIntelText(text);
  return mapBatch(attck, items);
}

async function mapFile(attck, filePath) {
  const buf = fs.readFileSync(filePath);
  const name = path.basename(filePath);
  const text = await extractFileText({
    buffer: buf,
    originalname: name,
    mimetype: ''
  });
  const mapped = await mapText(attck, text);
  return { text, mapped };
}

async function main() {
  loadMappingKnowledge();
  const attck = loadAttckData(getDefaultAttckPath());
  const all = hasFlag('all');
  const limit = all ? Infinity : Number(arg('limit', '120'));
  const minRecall = Number(arg('min-recall', '0.7'));
  const onlyExt = arg('ext', '');

  let pairs = listReportPairs();
  if (onlyExt) {
    const e = onlyExt.startsWith('.') ? onlyExt.toLowerCase() : `.${onlyExt.toLowerCase()}`;
    pairs = pairs.filter((p) => p.ext === e);
  }
  pairs = pairs.slice(0, limit);

  console.log(`pairs=${pairs.length} minAvailRecall=${minRecall}`);
  const rows = [];
  const byExt = {};
  const methodTotals = {};
  const t0 = Date.now();

  for (let i = 0; i < pairs.length; i++) {
    const p = pairs[i];
    process.stdout.write(`\r[${i + 1}/${pairs.length}] Report_${p.id}${p.ext}   `);
    try {
      const goldText = fs.readFileSync(p.jsonPath, 'utf8');
      const goldMapped = await mapText(attck, goldText);
      const gold = collectFromMapped(goldMapped);

      const { text, mapped: predMapped } = await mapFile(attck, p.reportPath);
      const pred = collectFromMapped(predMapped);
      const textLower = undefangText(text || '').toLowerCase();

      
      const goldIocInText = new Set();
      for (const row of goldMapped) {
        for (const ioc of row.iocs || []) {
          if (ioc?.value && valueInText(ioc.value, textLower)) goldIocInText.add(iocKey(ioc));
        }
      }
      const goldTechInText = new Set();
      for (const id of gold.techs) {
        if (textLower.includes(id.toLowerCase())) goldTechInText.add(id);
      }

      let iocHit = 0;
      for (const g of gold.iocs) if (pred.iocs.has(g)) iocHit += 1;
      let iocAvailHit = 0;
      for (const g of goldIocInText) if (pred.iocs.has(g)) iocAvailHit += 1;
      let techHit = 0;
      for (const g of gold.techs) if (pred.techs.has(g)) techHit += 1;
      let techAvailHit = 0;
      for (const g of goldTechInText) if (pred.techs.has(g)) techAvailHit += 1;

      const iocRecall = recall(gold.iocs, pred.iocs);
      const iocAvailRecall = recall(goldIocInText, pred.iocs);
      const techRecall = recall(gold.techs, pred.techs);
      const techAvailRecall = recall(goldTechInText, pred.techs);
      const iocPrec = pred.iocs.size ? iocHit / pred.iocs.size : 1;
      const techPrec = pred.techs.size ? techHit / pred.techs.size : 1;
      const ok = iocAvailRecall >= minRecall;

      for (const [k, v] of Object.entries(pred.methods || {})) {
        methodTotals[k] = (methodTotals[k] || 0) + v;
      }

      const row = {
        id: p.id,
        file: p.file,
        ext: p.ext,
        goldIoc: gold.iocs.size,
        goldIocInText: goldIocInText.size,
        predIoc: pred.iocs.size,
        iocRecall: Number(iocRecall.toFixed(3)),
        iocAvailRecall: Number(iocAvailRecall.toFixed(3)),
        iocPrecision: Number(iocPrec.toFixed(3)),
        iocHit,
        iocAvailHit,
        goldTech: gold.techs.size,
        goldTechInText: goldTechInText.size,
        predTech: pred.techs.size,
        techRecall: Number(techRecall.toFixed(3)),
        techAvailRecall: Number(techAvailRecall.toFixed(3)),
        techPrecision: Number(techPrec.toFixed(3)),
        techHit,
        avgConf: Number(pred.avgConf.toFixed(3)),
        tacticCount: pred.tacticCount,
        methods: pred.methods,
        textLen: (text || '').length,
        ok
      };
      rows.push(row);

      if (!byExt[p.ext]) {
        byExt[p.ext] = {
          n: 0,
          ok: 0,
          avgIocRecall: 0,
          avgIocAvailRecall: 0,
          avgTechRecall: 0,
          avgTechAvailRecall: 0,
          avgIocPrecision: 0,
          avgTechPrecision: 0,
          avgConf: 0,
          avgTextLen: 0,
          avgGoldIoc: 0,
          avgGoldTech: 0,
          errors: 0
        };
      }
      const b = byExt[p.ext];
      b.n += 1;
      if (ok) b.ok += 1;
      b.avgIocRecall += iocRecall;
      b.avgIocAvailRecall += iocAvailRecall;
      b.avgTechRecall += techRecall;
      b.avgTechAvailRecall += techAvailRecall;
      b.avgIocPrecision += iocPrec;
      b.avgTechPrecision += techPrec;
      b.avgConf += pred.avgConf;
      b.avgTextLen += (text || '').length;
      b.avgGoldIoc += gold.iocs.size;
      b.avgGoldTech += gold.techs.size;
    } catch (e) {
      rows.push({ id: p.id, file: p.file, ext: p.ext, error: e.message, ok: false });
      if (!byExt[p.ext]) {
        byExt[p.ext] = {
          n: 0,
          ok: 0,
          avgIocRecall: 0,
          avgIocAvailRecall: 0,
          avgTechRecall: 0,
          avgTechAvailRecall: 0,
          avgIocPrecision: 0,
          avgTechPrecision: 0,
          avgConf: 0,
          avgTextLen: 0,
          avgGoldIoc: 0,
          avgGoldTech: 0,
          errors: 0
        };
      }
      byExt[p.ext].n += 1;
      byExt[p.ext].errors += 1;
    }
  }
  console.log('');

  for (const b of Object.values(byExt)) {
    if (b.n - b.errors > 0) {
      const d = b.n - b.errors;
      for (const k of [
        'avgIocRecall',
        'avgIocAvailRecall',
        'avgTechRecall',
        'avgTechAvailRecall',
        'avgIocPrecision',
        'avgTechPrecision',
        'avgConf'
      ]) {
        b[k] = Number((b[k] / d).toFixed(4));
      }
      b.avgTextLen = Math.round(b.avgTextLen / d);
      b.avgGoldIoc = Number((b.avgGoldIoc / d).toFixed(2));
      b.avgGoldTech = Number((b.avgGoldTech / d).toFixed(2));
    }
  }

  const good = rows.filter((r) => !r.error);
  const methodSum = Object.values(methodTotals).reduce((a, b) => a + b, 0) || 1;
  const methodShare = {};
  for (const [k, v] of Object.entries(methodTotals)) {
    methodShare[k] = Number(((100 * v) / methodSum).toFixed(2));
  }
  const summary = {
    total: rows.length,
    ok: rows.filter((r) => r.ok).length,
    elapsedSec: Number(((Date.now() - t0) / 1000).toFixed(1)),
    avgIocRecall: good.length
      ? Number((good.reduce((s, r) => s + r.iocRecall, 0) / good.length).toFixed(4))
      : 0,
    avgIocAvailRecall: good.length
      ? Number((good.reduce((s, r) => s + r.iocAvailRecall, 0) / good.length).toFixed(4))
      : 0,
    avgTechRecall: good.length
      ? Number((good.reduce((s, r) => s + r.techRecall, 0) / good.length).toFixed(4))
      : 0,
    avgTechAvailRecall: good.length
      ? Number((good.reduce((s, r) => s + r.techAvailRecall, 0) / good.length).toFixed(4))
      : 0,
    avgIocPrecision: good.length
      ? Number((good.reduce((s, r) => s + (r.iocPrecision || 0), 0) / good.length).toFixed(4))
      : 0,
    avgTechPrecision: good.length
      ? Number((good.reduce((s, r) => s + (r.techPrecision || 0), 0) / good.length).toFixed(4))
      : 0,
    avgConf: good.length
      ? Number((good.reduce((s, r) => s + (r.avgConf || 0), 0) / good.length).toFixed(4))
      : 0,
    methodShare,
    byExt
  };

  const out = {
    opts: { all, limit: all ? null : limit, exts: onlyExt || null, minRecall },
    summary,
    rows
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out, null, 2), 'utf8');
  console.log(JSON.stringify(summary, null, 2));
  console.log('wrote', OUT);

  const misses = good.filter((r) => !r.ok).sort((a, b) => a.iocAvailRecall - b.iocAvailRecall);
  if (misses.length) {
    console.log('\nLowest available IOC recall:');
    for (const m of misses.slice(0, 12)) {
      console.log(
        `  Report_${m.id}${m.ext} avail=${m.iocAvailRecall} goldInText=${m.goldIocInText} pred=${m.predIoc}`
      );
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
