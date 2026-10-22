(function () {
  const API_BASE = window.QY_API_BASE || '/api';

  const state = {
    llmMapEnabled: false,
    llmAnalyzeEnabled: false,
    file: null,
    
    preferredSource: null,
    
    sourceExplicit: false,
    mapped: [],
    stats: null,
    coverage: [],
    coverageMeta: null,
    analysis: null,
    batchId: '',
    cumulative: { mappedIntelCount: 0, iocTotal: 0 },
    
    samplePreviewKey: null,
    samplePreviewContent: '',
    samplePreviewName: '',
    
    iocColumns: [
      { key: 'malware', label: 'malware' },
      { key: 'domain', label: 'domain' },
      { key: 'ip', label: 'ip' },
      { key: 'url', label: 'url' },
      { key: 'vulnerability', label: 'vulnerability' },
      { key: 'registry', label: 'registry' },
      { key: 'filepath', label: 'filepath' },
      { key: 'filename', label: 'filename' },
      { key: 'email', label: 'email' }
    ]
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  
  function renderInlineMd(text) {
    
    let s = escapeHtml(String(text || '').replace(/\u0000/g, ''));
    const slots = [];
    const park = (html) => {
      const token = `%%MDSLOT${slots.length}%%`;
      slots.push(html);
      return token;
    };
    const markIds = (chunk) =>
      chunk
        .replace(/\b(T\d{4}(?:\.\d{3})?)\b/g, '<code class="md-tech-id">$1</code>')
        .replace(/\b(TA\d{4})\b/g, '<code class="md-tactic-id">$1</code>');

    s = s.replace(/`([^`]+)`/g, (_, c) => park(`<code>${c}</code>`));
    s = s.replace(/\*\*([^*]+)\*\*/g, (_, c) => park(`<strong>${markIds(c)}</strong>`));
    s = markIds(s);
    s = s.replace(/%%MDSLOT(\d+)%%/g, (_, i) => slots[Number(i)] || '');
    return s;
  }

  
  function renderMarkdown(src) {
    const lines = String(src || '').replace(/\r\n/g, '\n').split('\n');
    const html = [];
    let i = 0;
    let inUl = false;
    let inOl = false;

    const closeLists = () => {
      if (inUl) {
        html.push('</ul>');
        inUl = false;
      }
      if (inOl) {
        html.push('</ol>');
        inOl = false;
      }
    };

    while (i < lines.length) {
      const raw = lines[i];
      const line = raw.trimEnd();
      const trimmed = line.trim();

      if (!trimmed) {
        closeLists();
        i += 1;
        continue;
      }

      if (/^---+$/.test(trimmed) || /^\*\*\*+$/.test(trimmed)) {
        closeLists();
        html.push('<hr class="md-hr" />');
        i += 1;
        continue;
      }

      const h = trimmed.match(/^(#{1,4})\s+(.+)$/);
      if (h) {
        closeLists();
        const level = h[1].length;
        html.push(`<h${level} class="md-h${level}">${renderInlineMd(h[2])}</h${level}>`);
        i += 1;
        continue;
      }

      if (/^>\s?/.test(trimmed)) {
        closeLists();
        const quote = [];
        while (i < lines.length && /^>\s?/.test(lines[i].trim())) {
          quote.push(lines[i].trim().replace(/^>\s?/, ''));
          i += 1;
        }
        html.push(`<blockquote class="md-quote">${renderInlineMd(quote.join(' '))}</blockquote>`);
        continue;
      }

      const ul = trimmed.match(/^[-*+]\s+(.+)$/);
      if (ul) {
        if (inOl) {
          html.push('</ol>');
          inOl = false;
        }
        if (!inUl) {
          html.push('<ul class="md-list">');
          inUl = true;
        }
        html.push(`<li>${renderInlineMd(ul[1])}</li>`);
        i += 1;
        continue;
      }

      const ol = trimmed.match(/^\d+[.)]\s+(.+)$/);
      if (ol) {
        if (inUl) {
          html.push('</ul>');
          inUl = false;
        }
        if (!inOl) {
          html.push('<ol class="md-list md-list-ol">');
          inOl = true;
        }
        html.push(`<li>${renderInlineMd(ol[1])}</li>`);
        i += 1;
        continue;
      }

      closeLists();
      const para = [trimmed];
      i += 1;
      while (i < lines.length) {
        const next = lines[i].trim();
        if (
          !next ||
          /^#{1,4}\s/.test(next) ||
          /^[-*+]\s+/.test(next) ||
          /^\d+[.)]\s+/.test(next) ||
          /^>\s?/.test(next) ||
          /^---+$/.test(next)
        ) {
          break;
        }
        para.push(next);
        i += 1;
      }
      html.push(`<p class="md-p">${renderInlineMd(para.join(' '))}</p>`);
    }

    closeLists();
    return html.join('\n') || '<p class="md-p">（无分析内容）</p>';
  }

  function renderAnalysisFromSections(sections) {
    const root = document.createElement('div');
    root.className = 'analysis-md';

    const h2 = document.createElement('h2');
    h2.className = 'md-h2';
    h2.textContent = sections.title || '分析摘要';
    root.appendChild(h2);

    if (sections.summary) {
      const p = document.createElement('p');
      p.className = 'md-p';
      p.textContent = sections.summary;
      root.appendChild(p);
    }

    const h3 = document.createElement('h3');
    h3.className = 'md-h3';
    h3.textContent = '主要技战术分布（MITRE ATT&CK）';
    root.appendChild(h3);

    const tactics = Array.isArray(sections.tactics) ? sections.tactics : [];

    if (!tactics.length) {
      const empty = document.createElement('p');
      empty.className = 'md-p';
      empty.textContent = '无命中战术';
      root.appendChild(empty);
    } else {
      tactics.forEach((tac) => {
        const h4 = document.createElement('h4');
        h4.className = 'md-h4';
        const techCount = Array.isArray(tac.techniques) ? tac.techniques.length : 0;
        h4.textContent =
          tac.id && tac.id !== 'UNKNOWN'
            ? `${tac.name || ''}（${tac.id}）· ${techCount} 项技术`
            : `${tac.name || '未归类'} · ${techCount} 项技术`;
        root.appendChild(h4);

        const ul = document.createElement('ul');
        ul.className = 'md-list';
        (tac.techniques || []).forEach((t) => {
          const li = document.createElement('li');
          const code = document.createElement('code');
          code.className = 'md-tech-id';
          code.textContent = t.id || '';
          li.appendChild(code);
          if (t.name && t.name !== t.id) {
            li.appendChild(document.createTextNode(` ${t.name}`));
          }
          ul.appendChild(li);
        });
        root.appendChild(ul);
      });
    }

    const h3ioc = document.createElement('h3');
    h3ioc.className = 'md-h3';
    h3ioc.textContent = 'IOC 统计';
    root.appendChild(h3ioc);

    const iocP = document.createElement('p');
    iocP.className = 'md-p analysis-ioc-summary';
    iocP.textContent = sections.iocSummary || '无';
    root.appendChild(iocP);

    if (sections.footer) {
      const q = document.createElement('blockquote');
      q.className = 'md-quote';
      q.textContent = sections.footer;
      root.appendChild(q);
    }

    return root;
  }

  function renderAnalysisPlain(text) {
    const root = document.createElement('div');
    root.className = 'analysis-md analysis-plain';
    const pre = document.createElement('pre');
    pre.className = 'analysis-pre';
    pre.textContent = text || '（无分析内容）';
    root.appendChild(pre);
    return root;
  }

  
  function showAnalysis(pack) {
    const box = $('analysisBox');
    const sub = $('analysisSub');
    if (!box) return false;

    state.analysis = pack || null;
    box.innerHTML = '';
    box.scrollTop = 0;

    if (!pack) {
      box.className = 'analysis-box is-placeholder';
      box.textContent = '完成映射后，点击「分析」在此展示结果';
      if (sub) sub.textContent = '规则摘要或大模型研判结果（需先完成映射）';
      return false;
    }

    box.className = 'analysis-box has-md';
    try {
      if (pack.sections && Array.isArray(pack.sections.tactics)) {
        box.appendChild(renderAnalysisFromSections(pack.sections));
      } else {
        const text = String(
          typeof pack === 'string'
            ? pack
            : pack.analysis || pack.text || JSON.stringify(pack, null, 2)
        ).replace(/\u0000/g, '');
        const md = document.createElement('div');
        md.className = 'analysis-md';
        try {
          md.innerHTML = renderMarkdown(text);
          if (!(md.textContent || '').trim()) md.textContent = text;
        } catch (_) {
          md.textContent = text;
        }
        box.appendChild(md);
      }
    } catch (err) {
      console.error('[showAnalysis]', err);
      
      const fallback =
        (typeof pack === 'string' ? pack : pack.analysis || pack.sections?.summary || '') ||
        String(err);
      box.textContent = fallback || '分析结果渲染失败';
    }

    if (!(box.innerText || '').trim()) {
      box.textContent =
        (typeof pack === 'string' ? pack : pack.analysis || pack.sections?.summary || '') ||
        '分析结果为空';
    }

    box.scrollTop = 0;

    if (sub) {
      const model = (typeof pack === 'object' && pack.model) || '';
      sub.textContent =
        model === 'rule-engine' ? '规则引擎摘要' : model ? `模型：${model}` : '分析结果';
    }

    box.classList.add('analysis-flash');
    setTimeout(() => box.classList.remove('analysis-flash'), 900);
    return Boolean(box.innerText && box.innerText.trim().length > 8);
  }

  function renderAnalysis() {
    showAnalysis(state.analysis);
  }

  
  function buildRuleAnalysis(mapped) {
    const list = mapped || [];
    const byTactic = new Map();
    const techSet = new Set();
    let confSum = 0;
    let confN = 0;

    for (const r of list) {
      const maps =
        Array.isArray(r.techniqueMappings) && r.techniqueMappings.length
          ? r.techniqueMappings
          : r.mapping
            ? [r.mapping]
            : [];
      for (const m of maps) {
        const techId = m.primary || '';
        if (!techId) continue;
        techSet.add(techId);
        if (m.confidence != null) {
          confSum += Number(m.confidence) || 0;
          confN += 1;
        }
        const tacticId = m.tacticId || 'UNKNOWN';
        const tacticName = m.tacticName || (tacticId !== 'UNKNOWN' ? tacticId : '未归类');
        const order = m.killChainOrder != null ? m.killChainOrder : 99;
        if (!byTactic.has(tacticId)) {
          byTactic.set(tacticId, {
            id: tacticId,
            name: tacticName,
            order,
            techniques: new Map()
          });
        }
        const bucket = byTactic.get(tacticId);
        if (!bucket.techniques.has(techId)) {
          bucket.techniques.set(techId, {
            id: techId,
            name: m.techniqueName || techId
          });
        }
      }
    }

    const tactics = [...byTactic.values()]
      .sort((a, b) => (a.order || 99) - (b.order || 99) || String(a.id).localeCompare(String(b.id)))
      .map((tac) => ({
        id: tac.id,
        name: tac.name,
        order: tac.order,
        techniques: [...tac.techniques.values()].sort((a, b) =>
          String(a.id).localeCompare(String(b.id))
        )
      }));

    const iocCount = {};
    for (const r of list) {
      const cols = r.iocColumns || {};
      for (const [k, vals] of Object.entries(cols)) {
        const n = Array.isArray(vals) ? vals.length : 0;
        if (n) iocCount[k] = (iocCount[k] || 0) + n;
      }
      if (!Object.keys(cols).length && Array.isArray(r.iocs)) {
        for (const ioc of r.iocs) {
          const k = ioc.category || ioc.type || 'other';
          iocCount[k] = (iocCount[k] || 0) + 1;
        }
      }
    }
    const iocSummary =
      Object.entries(iocCount)
        .filter(([, v]) => v > 0)
        .sort((a, b) => b[1] - a[1])
        .map(([k, v]) => `${k} ${v}`)
        .join(' · ') || '无';

    const tacticTotal = 14;
    const tacticHit = tactics.filter((t) => t.id && t.id !== 'UNKNOWN').length;
    const avgConf = confN ? ((confSum / confN) * 100).toFixed(1) : '0.0';
    const summary = `共映射 ${list.length} 条情报。命中技术 ${techSet.size} 项，覆盖战术 ${tacticHit}/${tacticTotal}（${
      Math.round((tacticHit / tacticTotal) * 1000) / 10
    }%）。平均置信度 ${avgConf}%。`;

    return {
      analysis: summary,
      sections: {
        title: '规则引擎分析摘要',
        summary,
        tactics,
        iocSummary,
        footer: '启用「大模型辅助分析」后，将生成更深入的战役研判。'
      },
      model: 'rule-engine',
      sampleSize: list.length
    };
  }

  function normalizeAnalysisPayload(data) {
    if (!data) return null;
    const raw = data.analysis;
    let pack = null;
    if (typeof raw === 'string') {
      pack = { analysis: raw, sections: data.sections || null, model: data.model || 'llm' };
    } else if (raw && typeof raw === 'object') {
      pack = {
        analysis: raw.analysis || raw.text || '',
        sections: raw.sections || data.sections || null,
        model: raw.model || data.model || 'llm',
        valid: raw.valid,
        warning: raw.warning
      };
    } else if (data.sections) {
      pack = { analysis: data.analysis || '', sections: data.sections, model: data.model || 'llm' };
    }
    if (pack && data.valid === false) pack.valid = false;
    if (pack && data.warning) pack.warning = data.warning;
    return pack;
  }

  
  function isUsableLlmAnalysis(pack) {
    if (!pack) return false;
    if (pack.valid === false) return false;
    if (pack.sections && Array.isArray(pack.sections.tactics)) return true;
    const text = String(pack.analysis || pack.text || '');
    if (text.length < 40) return false;
    const zh = (text.match(/[\u4e00-\u9fff]/g) || []).length;
    if (zh < 24) return false;
    if (/^(we need|let'?s |i will|i need to)\b/i.test(text.trim())) return false;
    return true;
  }

  
  function slimMappedForAnalyze(mapped) {
    return (mapped || []).map((r) => ({
      title: r.title,
      threatType: r.threatType,
      source: r.source,
      sourceId: r.sourceId || r.rid || r.id,
      techniqueMappings: (r.techniqueMappings || []).map((m) => ({
        primary: m.primary,
        techniqueName: m.techniqueName || m.displayName,
        displayName: m.displayName,
        tacticId: m.tacticId,
        tacticName: m.tacticName,
        killChainOrder: m.killChainOrder,
        confidence: m.confidence,
        method: m.method
      })),
      mapping: r.mapping
        ? {
            primary: r.mapping.primary,
            techniqueName: r.mapping.techniqueName || r.mapping.displayName,
            tacticId: r.mapping.tacticId,
            tacticName: r.mapping.tacticName,
            killChainOrder: r.mapping.killChainOrder,
            confidence: r.mapping.confidence,
            method: r.mapping.method
          }
        : undefined,
      iocSummary: r.iocSummary,
      
      iocs: (r.iocs || []).map((x) => ({
        type: x.type,
        category: x.category,
        value: x.value
      })),
      iocColumns: r.iocColumns || {}
    }));
  }

  let analyzing = false;

  async function doAnalyze() {
    if (analyzing) return;
    if (!state.mapped.length) {
      alert('请先完成映射');
      return;
    }

    analyzing = true;
    const btn = $('btnAnalyze');
    const box = $('analysisBox');
    if (btn) btn.disabled = true;
    if (box) {
      box.className = 'analysis-box';
      box.textContent = '分析中…';
    }

    let pack = null;
    try {
      
      pack = buildRuleAnalysis(state.mapped);
      showAnalysis(pack);

      if (state.llmAnalyzeEnabled) {
        if ($('analysisSub')) $('analysisSub').textContent = '大模型分析中…';
        const body = JSON.stringify({
          mapped: slimMappedForAnalyze(state.mapped),
          batchId: state.batchId || '',
          llmMapEnabled: false,
          llmAnalyzeEnabled: true,
          llmEnabled: true
        });
        const data = await api('/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body
        });
        const next = normalizeAnalysisPayload(data);
        if (isUsableLlmAnalysis(next)) {
          pack = next;
          showAnalysis(pack);
        } else {
          showAnalysis(pack);
          if ($('analysisSub')) {
            const why =
              (data && (data.analysis?.error || data.analysis?.warning || data.error)) ||
              (next && next.warning) ||
              '';
            $('analysisSub').textContent = why
              ? `大模型未采用（${String(why).slice(0, 80)}），已保留规则引擎摘要`
              : '大模型返回无效内容，已保留规则引擎摘要';
          }
        }
        if (data.stats) state.stats = data.stats;
        if (data.coverage) {
          state.coverage = coverageMatrixOf(data.coverage);
          renderCoverage();
        }
      }

      if (box) box.scrollTop = 0;
      $('panelAnalysis')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      console.error('[analyze]', e);
      if (pack) {
        try {
          showAnalysis(pack);
        } catch (_) {
          
        }
      }
      if (box && !(box.innerText || '').trim()) {
        box.className = 'analysis-box has-md';
        box.textContent = `分析失败：${e.message || e}`;
      }
      if ($('analysisSub')) {
        $('analysisSub').textContent = `分析异常：${e.message || e}`;
      }
    } finally {
      analyzing = false;
      if (btn) btn.disabled = false;
    }
  }

  window.__qyAnalyze = function () {
    try {
      const p = doAnalyze();
      if (p && typeof p.catch === 'function') {
        p.catch((err) => {
          console.error('[analyze]', err);
          alert(`分析失败：${err && err.message ? err.message : err}`);
        });
      }
    } catch (err) {
      console.error('[analyze sync]', err);
      alert(`分析失败：${err && err.message ? err.message : err}`);
    }
    return false;
  };
  window.__qyMap = function () {
    return doMap();
  };
  window.QY_TI = {
    getState: () => state,
    doAnalyze,
    doMap,
    buildRuleAnalysis,
    showAnalysis
  };

  function wireAnalyzeButton() {
    const btn = document.getElementById('btnAnalyze');
    if (!btn || btn.dataset.qyWired === '1') return;
    btn.dataset.qyWired = '1';
    btn.addEventListener('click', (ev) => {
      ev.preventDefault();
      window.__qyAnalyze();
    });
  }
  wireAnalyzeButton();

  async function api(path, opts = {}) {
    const res = await fetch(`${API_BASE}${path}`, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText || '请求失败');
    return data;
  }

  function getInputSnapshot() {
    const text = ($('intelText')?.value || '').trim();
    return {
      file: state.file,
      text,
      hasFile: Boolean(state.file),
      hasText: Boolean(text)
    };
  }

  function hasInput() {
    const { hasFile, hasText } = getInputSnapshot();
    return hasFile || hasText;
  }

  
  function syncInputSourceUI() {
    const { hasFile, hasText, file, text } = getInputSnapshot();
    const bar = $('inputSourceBar');
    const status = $('inputSourceStatus');
    const pick = $('inputSourcePick');
    if (!bar || !status) return;

    $('colFile')?.classList.remove('is-active', 'is-dimmed');
    $('colText')?.classList.remove('is-active', 'is-dimmed');

    if (hasFile && hasText) {
      if (!state.sourceExplicit) state.preferredSource = null;
      bar.dataset.state = 'conflict';
      if (pick) pick.hidden = false;
      const choice = state.preferredSource;
      if ($('sourceFile')) $('sourceFile').checked = choice === 'file';
      if ($('sourceText')) $('sourceText').checked = choice === 'text';
      if (choice === 'file') {
        status.textContent = `已选择使用文件「${file.name}」（文本框内容本次不参与映射）`;
        $('colFile')?.classList.add('is-active');
        $('colText')?.classList.add('is-dimmed');
      } else if (choice === 'text') {
        status.textContent = `已选择使用文本框（${text.length} 字）（已选文件本次不参与映射）`;
        $('colText')?.classList.add('is-active');
        $('colFile')?.classList.add('is-dimmed');
      } else {
        status.textContent = '检测到文件与文本同时存在，请选择本次映射使用哪一项，或先清除其中一侧';
      }
      return;
    }

    if (pick) pick.hidden = true;
    state.sourceExplicit = false;
    if ($('sourceFile')) $('sourceFile').checked = false;
    if ($('sourceText')) $('sourceText').checked = false;

    if (hasFile) {
      state.preferredSource = 'file';
      bar.dataset.state = 'ready';
      status.textContent = `本次将使用文件：「${file.name}」`;
      $('colFile')?.classList.add('is-active');
      return;
    }
    if (hasText) {
      state.preferredSource = 'text';
      bar.dataset.state = 'ready';
      status.textContent = `本次将使用文本框内容（${text.length} 字）`;
      $('colText')?.classList.add('is-active');
      return;
    }

    state.preferredSource = null;
    bar.dataset.state = 'empty';
    status.textContent = '请上传文件或粘贴情报文本';
  }

  
  function askSourceModal() {
    return new Promise((resolve) => {
      const modal = $('sourceModal');
      if (!modal) {
        resolve(null);
        return;
      }
      const { file, text } = getInputSnapshot();
      if ($('sourceModalMsg')) {
        $('sourceModalMsg').textContent =
          `当前同时存在已选文件「${file?.name || ''}」与文本框内容（${text.length} 字）。请确认本次映射使用哪一项。`;
      }
      if ($('sourceModalFile')) {
        $('sourceModalFile').textContent = `使用文件「${file?.name || ''}」`;
      }

      const finish = (value) => {
        modal.hidden = true;
        modal.removeEventListener('click', onBackdrop);
        $('sourceModalClose')?.removeEventListener('click', onCancel);
        $('sourceModalFile')?.removeEventListener('click', onFile);
        $('sourceModalText')?.removeEventListener('click', onText);
        document.removeEventListener('keydown', onKey);
        resolve(value);
      };
      const onCancel = () => finish(null);
      const onFile = () => finish('file');
      const onText = () => finish('text');
      const onBackdrop = (e) => {
        if (e.target === modal) finish(null);
      };
      const onKey = (e) => {
        if (e.key === 'Escape') finish(null);
      };

      $('sourceModalClose')?.addEventListener('click', onCancel);
      $('sourceModalFile')?.addEventListener('click', onFile);
      $('sourceModalText')?.addEventListener('click', onText);
      modal.addEventListener('click', onBackdrop);
      document.addEventListener('keydown', onKey);
      modal.hidden = false;
    });
  }

  
  async function resolveInputSource() {
    const { hasFile, hasText } = getInputSnapshot();
    if (!hasFile && !hasText) return null;
    if (hasFile && !hasText) return 'file';
    if (!hasFile && hasText) return 'text';
    if (state.preferredSource === 'file' || state.preferredSource === 'text') {
      return state.preferredSource;
    }
    const chosen = await askSourceModal();
    if (chosen) {
      state.preferredSource = chosen;
      state.sourceExplicit = true;
      syncInputSourceUI();
    }
    return chosen;
  }

  
  function buildFormData(opts = {}) {
    const fd = new FormData();
    const { file, text } = getInputSnapshot();
    const source = opts.source || null;

    if (source === 'file') {
      if (file) fd.append('file', file);
    } else if (source === 'text') {
      if (text) fd.append('text', text);
    } else if (file && !text) {
      fd.append('file', file);
    } else if (text && !file) {
      fd.append('text', text);
    }

    const mapOn = state.llmMapEnabled;
    const analyzeOn = opts.forAnalyze ? state.llmAnalyzeEnabled : false;
    fd.append('llmMapEnabled', mapOn ? 'true' : 'false');
    fd.append('llmAnalyzeEnabled', analyzeOn ? 'true' : 'false');
    fd.append('llmEnabled', (opts.forAnalyze ? analyzeOn : mapOn) ? 'true' : 'false');
    return fd;
  }

  function setLlmToggle(btnId, on, titleOn, titleOff) {
    const btn = $(btnId);
    if (!btn) return;
    btn.dataset.on = on ? 'true' : 'false';
    btn.title = on ? titleOn : titleOff;
  }

  function setLlmUi() {
    setLlmToggle(
      'btnLlmMapToggle',
      state.llmMapEnabled,
      '大模型辅助映射已开启',
      '大模型辅助映射已关闭（点击开启）'
    );
    setLlmToggle(
      'btnLlmAnalyzeToggle',
      state.llmAnalyzeEnabled,
      '大模型辅助分析已开启',
      '大模型辅助分析已关闭（点击开启）'
    );
  }

  
  function countSessionIps(s) {
    const byCol = s?.iocByColumn || {};
    if (typeof byCol.ip === 'number') return byCol.ip;
    const by = s?.iocByType || {};
    return (Number(by.ipv4) || 0) + (Number(by.ipv6) || 0) + (Number(by.ip) || 0);
  }

  function renderTopStats() {
    const s = state.stats || {};
    const cum = state.cumulative || {};
    const tacticHit = s.tacticCoverageCount || 0;
    const tacticTotal = s.tacticTotal || 14;
    const techHit = s.techniqueCount || 0;

    const setTxt = (id, val) => {
      const el = $(id);
      if (el) el.textContent = val;
    };

    setTxt('statMappedCum', String(cum.mappedIntelCount || 0));
    setTxt('statIocCum', String(cum.iocTotal || 0));
    setTxt('statMappedSession', String(tacticHit));
    setTxt('statTacticUnit', `/${tacticTotal}`);
    setTxt('statAccuracy', String(techHit));
    setTxt('statIocSession', String(s.iocTotal || 0));
    setTxt('statIocIp', String(countSessionIps(s)));

    const sessionZero = !(s.mappedCount > 0);
    document.querySelectorAll('.stat-metric.is-session').forEach((el) => {
      el.classList.toggle('fill-zero', sessionZero);
      el.classList.toggle('fill-done', !sessionZero);
    });

    if ($('statMappedSub')) {
      $('statMappedSub').textContent = s.mappedCount
        ? `本次 ${s.mappedCount} 条情报 · 技术 ${techHit} · 战术 ${tacticHit}/${tacticTotal}${
            s.llmAssistedCount ? ` · LLM辅助 ${s.llmAssistedCount}` : ''
          }`
        : '本次待执行映射';
    }
    if ($('statIocSub')) {
      const by = s.iocByColumn || s.iocByType || {};
      const top = Object.entries(by)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([k, v]) => `${k}:${v}`)
        .join(' · ');
      $('statIocSub').textContent = top || '等待映射后统计';
    }
  }

  function colCount() {
    return 6 + (state.iocColumns?.length || 0);
  }

  function renderTableHead() {
    const head = $('resultHead');
    if (!head) return;
    const iocTh = (state.iocColumns || [])
      .map((c) => `<th class="th-ioc">${escapeHtml(c.label || c.key)}</th>`)
      .join('');
    head.innerHTML = `<tr>
      <th class="th-title">标题</th>
      <th class="th-type">类型</th>
      <th class="th-tech">技术</th>
      <th class="th-tactic">战术</th>
      ${iocTh}
      <th class="th-method">方式</th>
      <th class="th-conf">置信度</th>
    </tr>`;
  }

  
  function formatIocCell(values) {
    const list = Array.isArray(values) ? values.filter(Boolean) : [];
    if (!list.length) {
      return { html: '<span class="ioc-na">N/A</span>', empty: true };
    }
    const title = escapeHtml(list.join('\n'));
    if (list.length === 1) {
      return {
        html: `<span class="ioc-vals" title="${title}">${escapeHtml(list[0])}</span>`,
        empty: false
      };
    }
    return {
      html: `<span class="ioc-vals" title="${title}">${escapeHtml(list[0])}<br><em>+${list.length - 1}</em></span>`,
      empty: false
    };
  }

  function formatTechCell(row) {
    const maps = Array.isArray(row.techniqueMappings) && row.techniqueMappings.length
      ? row.techniqueMappings
      : row.mapping
        ? [row.mapping]
        : [];
    const m = maps[0] || {};
    const n = maps.length || (m.primary ? 1 : 0);
    const primary = escapeHtml(m.primary || '-');
    if (n <= 1) {
      return `<span class="cell-stack"><span class="tech-id">${primary}</span></span>`;
    }
    return `<span class="cell-stack"><span class="tech-id">${primary}</span><span class="tech-count">等 ${n} 项</span></span>`;
  }

  function formatTacticCell(row) {
    const names = Array.isArray(row.tacticNames) && row.tacticNames.length
      ? row.tacticNames
      : row.mapping?.tacticName
        ? [row.mapping.tacticName]
        : [];
    if (!names.length) {
      return `<span class="cell-stack">${escapeHtml(row.mapping?.tacticId || '-')}</span>`;
    }
    if (names.length === 1) {
      return `<span class="cell-stack">${escapeHtml(names[0])}</span>`;
    }
    return `<span class="cell-stack">${escapeHtml(names[0])}<span class="tech-count">等 ${names.length} 个</span></span>`;
  }

  function renderTable() {
    const body = $('resultBody');
    const table = $('resultTable');
    const scroll = $('resultTableScroll');
    const emptyMsg = $('resultEmptyMsg');

    if (!state.mapped.length) {
      if (scroll) scroll.classList.add('is-empty');
      if (table) table.hidden = true;
      if (emptyMsg) emptyMsg.hidden = false;
      if (body) body.innerHTML = '';
      return;
    }

    if (scroll) scroll.classList.remove('is-empty');
    if (table) table.hidden = false;
    if (emptyMsg) emptyMsg.hidden = true;

    renderTableHead();
    body.innerHTML = state.mapped
      .map((row, idx) => {
        const m = row.mapping || {};
        const conf = Math.round((m.confidence || 0) * 100);
        const cols = row.iocColumns || {};
        const iocCells = (state.iocColumns || [])
          .map((c) => {
            const cell = formatIocCell(cols[c.key]);
            return `<td class="cell-ioc${cell.empty ? ' is-empty' : ''}">${cell.html}</td>`;
          })
          .join('');
        return `<tr data-idx="${idx}" class="row-clickable">
          <td class="cell-text">${escapeHtml(row.title || '')}</td>
          <td class="cell-type">${escapeHtml(row.threatType || '-')}</td>
          <td class="cell-tech">${formatTechCell(row)}</td>
          <td class="cell-tactic">${formatTacticCell(row)}</td>
          ${iocCells}
          <td class="cell-method">${escapeHtml(m.methodLabel || m.method || '-')}</td>
          <td class="cell-conf"><span class="badge quality-${escapeHtml(m.quality || 'poor')}">${conf}%</span></td>
        </tr>`;
      })
      .join('');
  }

  function normalizeTechniqueList(t) {
    let list = [];
    if (Array.isArray(t.techniqueList) && t.techniqueList.length) {
      list = t.techniqueList.map((x) => ({
        id: x.id,
        name: x.name || x.id,
        count: x.count || 1,
        sourceIds: x.sourceIds
      }));
    } else {
      const raw = t.techniques || {};
      list = Object.entries(raw).map(([id, countOrObj]) => {
        if (countOrObj && typeof countOrObj === 'object') {
          return {
            id: countOrObj.id || id,
            name: countOrObj.name || id,
            count: countOrObj.count || 1,
            sourceIds: countOrObj.sourceIds
          };
        }
        return { id, name: id, count: Number(countOrObj) || 1 };
      });
    }
    
    const ids = new Set(list.map((x) => x.id));
    list = list.filter((x) => {
      const id = String(x.id || '');
      if (!id || id.includes('.')) return true;
      for (const other of ids) {
        if (String(other).startsWith(id + '.')) return false;
      }
      return true;
    });
    return list.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  }

  function coverageMatrixOf(coverage) {
    if (Array.isArray(coverage)) return coverage;
    if (coverage && Array.isArray(coverage.matrix)) return coverage.matrix;
    return [];
  }

  function renderCoverage() {
    const box = $('coverageMatrix');
    const cov = coverageMatrixOf(state.coverage);
    if (!cov.length) {
      box.className = 'matrix is-empty';
      box.innerHTML = '<div class="empty-state">映射后展示技战术覆盖矩阵</div>';
      return;
    }
    box.className = 'matrix attack-matrix';
    const placed = cov.reduce((n, t) => n + normalizeTechniqueList(t).length, 0);
    const orphans = state.coverageMeta?.orphanTechniques || [];
    box.innerHTML =
      cov
        .map((t) => {
          const techs = normalizeTechniqueList(t);
          const on = (t.count || 0) > 0 || techs.length > 0;
          const techHtml = techs.length
            ? techs
                .map((tech) => {
                  const src =
                    Array.isArray(tech.sourceIds) && tech.sourceIds.length
                      ? `来源: ${tech.sourceIds.join(', ')}`
                      : '';
                  return `<div class="attack-tech" title="${escapeHtml(
                    [tech.name || tech.id, src].filter(Boolean).join(' · ')
                  )}">
                    <span class="attack-tech-id">${escapeHtml(tech.id)}</span>
                    <span class="attack-tech-name">${escapeHtml(tech.name || '')}</span>
                  </div>`;
                })
                .join('')
            : `<div class="attack-tech is-empty">—</div>`;
          return `<div class="matrix-cell attack-col ${on ? 'covered' : 'uncovered'}" title="${escapeHtml(
            t.nameEn || t.name || ''
          )}">
          <div class="attack-tactic-head">
            <div class="tname">${escapeHtml(t.name || t.id)}</div>
            <div class="tid">${escapeHtml(t.id || '')}</div>
          </div>
          <div class="attack-tech-stack">${techHtml}</div>
        </div>`;
        })
        .join('') +
      (orphans.length
        ? `<div class="matrix-orphan-note">另有 ${orphans.length} 项技术暂无战术落点：${orphans
            .map((o) => escapeHtml(o.id))
            .join(', ')}</div>`
        : '') +
      `<div class="matrix-count-note">覆盖 ATT&ampCK 矩阵攻击技术（含子技术） ${placed} 项</div>`;
  }

  function applyResult(data) {
    state.batchId = data.batchId || '';
    state.mapped = data.mapped || data.items || [];
    state.stats = data.stats || null;
    state.coverage = coverageMatrixOf(data.coverage);
    state.coverageMeta = data.coverageMeta || null;
    
    $('batchIdLabel').textContent = state.batchId ? `batch: ${state.batchId}` : '';
    const rawN = data.stats?.rawTechniqueCount;
    const techN = data.stats?.techniqueCount || data.stats?.techniqueHitCount || 0;
    const tacN = data.stats?.tacticCoverageCount || 0;
    $('batchHint').textContent =
      rawN && rawN !== techN
        ? `映射完成：${state.mapped.length} 条情报 · 报告技术 ${rawN} 项，命中 ${techN} 项 · 战术 ${tacN} · 点击行查看详情`
        : `映射完成：${state.mapped.length} 条情报 · ${techN} 项技术 · 战术 ${tacN} · 点击行查看详情`;
    $('btnSave').hidden = !state.mapped.length;
    $('btnSaveStats').hidden = !state.stats;
    if (state.file) setFileUiState('done', { message: '已映射' });
    renderTopStats();
    renderTable();
    renderCoverage();
    
    renderAnalysis();
  }

  
  function collectOfficialRenames(maps) {
    const lines = [];
    const seen = new Set();
    for (const t of maps || []) {
      const primary = String(t.primary || '').toUpperCase();
      if (!primary) continue;
      const sources = Array.isArray(t.sourceIds) ? t.sourceIds : [];
      for (const raw of sources) {
        const src = String(raw || '').toUpperCase();
        if (!src || src === primary) continue;
        const key = `${src}→${primary}`;
        if (seen.has(key)) continue;
        seen.add(key);
        lines.push(`${src} → ${primary}`);
      }
    }
    lines.sort((a, b) => a.localeCompare(b, 'en'));
    return lines;
  }

  function openDetail(idx) {
    const row = state.mapped[idx];
    if (!row) return;
    const m = row.mapping || {};
    $('detailTitle').textContent = '映射详情';
    const entryName = String(row.title || '').trim() || '未命名条目';
    const maps =
      Array.isArray(row.techniqueMappings) && row.techniqueMappings.length
        ? row.techniqueMappings
        : m.primary
          ? [m]
          : [];

    
    const primaryConfPct = Math.round((Number(m.confidence) || 0) * 100);
    const rawN =
      row.rawTechniqueCount || (row.rawTechniqueIds || []).length || maps.length;
    const methodText = [
      m.methodLabel || m.method || '-',
      row.llmAssisted ? 'LLM' : '',
      row.vectorAssisted ? 'Vector' : '',
    ]
      .filter(Boolean)
      .join(' · ');

    const techList = maps.length
      ? `<ul class="detail-tech-list">${maps
          .map((t) => {
            const id = String(t.primary || '').toUpperCase();
            const name = t.displayName || t.techniqueName || '';
            const nameShow = name && name !== id ? name : t.techniqueNameEn || '';
            const tactic = t.tacticName || t.tacticId || '';
            const conf =
              t.confidence != null ? `${Math.round(Number(t.confidence) * 100)}%` : '';
            const rename =
              t.resolvedFrom && String(t.resolvedFrom).toUpperCase() !== id
                ? String(t.resolvedFrom).toUpperCase()
                : '';
            const metaParts = [
              tactic ? `战术 ${tactic}` : '',
              conf ? `置信度 ${conf}` : '',
              t.methodLabel || t.method || '',
              rename ? `来源 ${rename}` : '',
            ].filter(Boolean);
            return `<li class="detail-tech-item">
              <code class="detail-tech-id">${escapeHtml(id)}</code>
              <div class="detail-tech-body">
                <div class="detail-tech-name">${escapeHtml(nameShow || id)}</div>
                ${
                  metaParts.length
                    ? `<div class="detail-tech-meta">${escapeHtml(metaParts.join('  ·  '))}</div>`
                    : ''
                }
              </div>
            </li>`;
          })
          .join('')}</ul>`
      : '<p class="detail-empty">暂无技术映射</p>';

    const cols = row.iocColumns || {};
    const iocDefs = state.iocColumns || [];
    const filledIocs = [];
    const emptyIocLabels = [];
    iocDefs.forEach((c) => {
      const vals = cols[c.key] || [];
      if (vals.length) filledIocs.push({ c, vals });
      else emptyIocLabels.push(c.label || c.key);
    });

    const iocColsHtml = filledIocs.length
      ? filledIocs
          .map(({ c, vals }) => {
            const chips = vals
              .map((v) => `<span class="ioc-chip" title="${escapeHtml(v)}">${escapeHtml(v)}</span>`)
              .join('');
            return `<div class="detail-ioc-block">
              <div class="detail-ioc-label">${escapeHtml(c.label || c.key)}<span class="detail-count">${vals.length}</span></div>
              <div class="ioc-chip-wrap">${chips}</div>
            </div>`;
          })
          .join('') +
        (emptyIocLabels.length
          ? `<p class="detail-ioc-empty-note">其余类别无命中：${escapeHtml(emptyIocLabels.join('、'))}</p>`
          : '')
      : '<p class="detail-ioc-empty-note">暂无 IOC</p>';

    const renames = collectOfficialRenames(maps);
    const noteHtml = renames.length
      ? `<section class="detail-block">
          <h4 class="detail-block-title">编号更名<span class="detail-count">${renames.length}</span></h4>
          <ul class="rename-list">${renames
            .map((t) => `<li class="rename-item">${escapeHtml(t)}</li>`)
            .join('')}</ul>
        </section>`
      : '';

    const metaRows = [
      ['威胁类型', escapeHtml(row.threatType || '-')],
      ['置信度', `<span class="detail-conf-main">${primaryConfPct}%</span>`],
      ['映射方式', escapeHtml(methodText)],
    ];

    $('detailBody').innerHTML = `
      <div class="detail-entry">
        <div class="detail-entry-label">条目名称</div>
        <div class="detail-entry-name" title="${escapeHtml(entryName)}">${escapeHtml(entryName)}</div>
      </div>

      <section class="detail-block">
        <h4 class="detail-block-title">基本信息</h4>
        <dl class="detail-meta">
          ${metaRows
            .map(
              ([k, v]) => `<div class="detail-meta-row">
              <dt>${k}</dt>
              <dd>${v}</dd>
            </div>`
            )
            .join('')}
        </dl>
      </section>

      <section class="detail-block">
        <h4 class="detail-block-title">ATT&amp;CK 技术<span class="detail-count">${maps.length}${
          rawN !== maps.length ? ` / 原编号 ${rawN}` : ''
        }</span></h4>
        ${techList}
      </section>

      ${noteHtml}

      <section class="detail-block">
        <h4 class="detail-block-title">IOC 分列</h4>
        <div class="detail-ioc-grid">${iocColsHtml}</div>
      </section>
    `;
    $('detailModal').hidden = false;
  }

  async function runMapWithSource(source) {
    if (source === 'file' && !state.file) return alert('请先上传文件');
    if (source === 'text' && !getInputSnapshot().text) return alert('请先粘贴情报文本');

    const label =
      source === 'file'
        ? `文件「${state.file.name}」`
        : `文本框（${getInputSnapshot().text.length} 字）`;

    $('batchHint').textContent = state.llmMapEnabled
      ? `映射中（含大模型辅助 · ${label}）…`
      : `映射中（数据源：${label}）…`;
    if (source === 'file' && state.file) setFileUiState('mapping', { message: '上传并解析映射中…' });
    try {
      const data = await api('/mapping/batch', {
        method: 'POST',
        body: buildFormData({ source })
      });
      state.analysis = null;
      applyResult(data);
      const rawN = data.stats?.rawTechniqueCount;
      const techN = data.stats?.techniqueCount || 0;
      if ($('batchHint')) {
        $('batchHint').textContent =
          rawN && rawN !== techN
            ? `映射完成（数据源：${label}）：报告技术 ${rawN} 项，命中 ${techN} 项`
            : `映射完成（数据源：${label}）：${techN} 项技术`;
      }
    } catch (e) {
      alert(e.message);
      $('batchHint').textContent = '映射失败';
      if (source === 'file' && state.file) setFileUiState('error', { message: '映射失败' });
    }
  }

  async function doMap() {
    const source = await resolveInputSource();
    if (!source) {
      if (!hasInput()) alert('请先上传文件或粘贴情报文本');
      return;
    }
    await runMapWithSource(source);
  }

  async function doPersist(mode) {
    try {
      const body = {
        mode,
        batchId: state.batchId,
        mapped: state.mapped,
        stats: state.stats,
        coverage: state.coverage,
        analysis: state.analysis?.analysis || state.analysis || '',
        llmMapEnabled: state.llmMapEnabled,
        llmAnalyzeEnabled: state.llmAnalyzeEnabled,
        llmEnabled: state.llmMapEnabled || state.llmAnalyzeEnabled
      };
      const data = await api('/persist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      alert(data.message || data.title || '保存成功');
      await refreshCumulative();
    } catch (e) {
      alert(e.message);
    }
  }

  async function refreshCumulative() {
    try {
      const data = await api('/stats/cumulative');
      state.cumulative = data;
      renderTopStats();
    } catch (_) {
      
    }
  }

  function bindFile() {
    const drop = $('fileDrop');
    const input = $('fileInput');
    drop?.addEventListener('click', (e) => {
      if (e.target.closest('#btnClearFile')) return;
      input?.click();
    });
    drop?.addEventListener('dragover', (e) => {
      e.preventDefault();
      drop.classList.add('dragover');
    });
    drop?.addEventListener('dragleave', () => drop.classList.remove('dragover'));
    drop?.addEventListener('drop', (e) => {
      e.preventDefault();
      drop.classList.remove('dragover');
      const f = e.dataTransfer?.files?.[0];
      if (f) setFile(f);
    });
    input?.addEventListener('change', () => {
      const f = input.files?.[0];
      if (f) setFile(f);
    });
    $('btnClearFile')?.addEventListener('click', (e) => {
      e.stopPropagation();
      clearFile();
    });
    $('intelText')?.addEventListener('input', () => {
      const { hasFile, hasText } = getInputSnapshot();
      if (hasFile && hasText && !state.sourceExplicit) {
        state.preferredSource = null;
      } else if (!hasText && state.preferredSource === 'text') {
        state.preferredSource = null;
        state.sourceExplicit = false;
      }
      syncInputSourceUI();
    });
    $('sourceFile')?.addEventListener('change', () => {
      if ($('sourceFile').checked) {
        state.preferredSource = 'file';
        state.sourceExplicit = true;
        syncInputSourceUI();
      }
    });
    $('sourceText')?.addEventListener('change', () => {
      if ($('sourceText').checked) {
        state.preferredSource = 'text';
        state.sourceExplicit = true;
        syncInputSourceUI();
      }
    });
  }

  function formatFileSize(n) {
    if (!n && n !== 0) return '';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  }

  function setFileUiState(stateName, opts = {}) {
    const drop = $('fileDrop');
    const idle = $('fileIdle');
    const panel = $('fileSelectedPanel');
    const progress = $('fileProgress');
    const badge = $('fileBadge');
    const progressText = $('fileProgressText');
    if (drop) drop.dataset.state = stateName;

    if (stateName === 'idle') {
      if (idle) idle.hidden = false;
      if (panel) panel.hidden = true;
      if (progress) progress.hidden = true;
      return;
    }

    if (idle) idle.hidden = true;
    if (panel) panel.hidden = false;

    if (stateName === 'ready') {
      if (progress) progress.hidden = true;
      if (badge) {
        badge.hidden = false;
        badge.className = 'file-badge';
        badge.textContent = '已选择 · 待映射';
      }
    } else if (stateName === 'mapping') {
      if (progress) progress.hidden = false;
      if (progressText) progressText.textContent = opts.message || '上传并解析映射中…';
      if (badge) {
        badge.hidden = false;
        badge.className = 'file-badge is-busy';
        badge.textContent = '处理中';
      }
    } else if (stateName === 'done') {
      if (progress) progress.hidden = true;
      if (badge) {
        badge.hidden = false;
        badge.className = 'file-badge is-done';
        badge.textContent = opts.message || '已映射';
      }
    } else if (stateName === 'error') {
      if (progress) progress.hidden = true;
      if (badge) {
        badge.hidden = false;
        badge.className = 'file-badge is-busy';
        badge.textContent = opts.message || '失败';
      }
    }
  }

  function setFile(f) {
    state.file = f;
    const name = $('fileName');
    if (name) name.textContent = f.name;
    const meta = $('fileMeta');
    if (meta) {
      const ext = (f.name.split('.').pop() || '').toUpperCase();
      meta.textContent = `${ext || 'FILE'} · ${formatFileSize(f.size)}`;
    }
    setFileUiState('ready');
    const text = ($('intelText')?.value || '').trim();
    state.sourceExplicit = false;
    state.preferredSource = text ? null : 'file';
    syncInputSourceUI();
  }

  function clearFile() {
    state.file = null;
    state.sourceExplicit = false;
    if ($('fileInput')) $('fileInput').value = '';
    if ($('fileName')) $('fileName').textContent = '';
    if ($('fileMeta')) $('fileMeta').textContent = '';
    setFileUiState('idle');
    if (state.preferredSource === 'file') state.preferredSource = null;
    syncInputSourceUI();
  }

  function resetSamplePreview() {
    state.samplePreviewKey = null;
    state.samplePreviewContent = '';
    state.samplePreviewName = '';
    const preview = $('samplePreview');
    if (preview) {
      preview.textContent = '请选择左侧样本查看内容预览';
      preview.classList.remove('has-content');
    }
    const confirm = $('sampleConfirm');
    if (confirm) confirm.disabled = true;
    $('sampleList')?.querySelectorAll('.sample-item.is-selected').forEach((el) => {
      el.classList.remove('is-selected');
    });
  }

  function closeSampleModal() {
    const modal = $('sampleModal');
    if (modal) modal.hidden = true;
    resetSamplePreview();
  }

  async function openSamples() {
    try {
      const data = await api('/samples');
      const list = data.samples || [];
      resetSamplePreview();
      $('sampleList').innerHTML = list
        .map(
          (s) => `<button type="button" class="sample-item" data-key="${escapeHtml(s.sampleKey || s._id)}">
            <span class="sample-item-title">${escapeHtml(s.name)}</span>
            <span class="sample-item-desc">${escapeHtml(s.description || s.format || '')}</span>
          </button>`
        )
        .join('');
      $('sampleModal').hidden = false;
    } catch (e) {
      alert(e.message);
    }
  }

  async function previewSample(key) {
    try {
      const data = await api(`/samples/${encodeURIComponent(key)}`);
      state.samplePreviewKey = key;
      state.samplePreviewContent = data.content || '';
      state.samplePreviewName = data.name || key;

      $('sampleList')?.querySelectorAll('.sample-item').forEach((el) => {
        el.classList.toggle('is-selected', el.dataset.key === key);
      });

      const preview = $('samplePreview');
      if (preview) {
        preview.textContent = state.samplePreviewContent || '（该样本无内容）';
        preview.classList.toggle('has-content', Boolean(state.samplePreviewContent));
      }
      const confirm = $('sampleConfirm');
      if (confirm) confirm.disabled = !state.samplePreviewContent;
    } catch (e) {
      alert(e.message);
    }
  }

  function confirmSample() {
    if (!state.samplePreviewContent) {
      alert('请先选择一条样本并预览');
      return;
    }
    if ($('intelText')) $('intelText').value = state.samplePreviewContent;
    clearFile();
    state.preferredSource = 'text';
    state.sourceExplicit = false;
    syncInputSourceUI();
    closeSampleModal();
  }

  async function init() {
    try {
      setLlmUi();
    } catch (e) {
      console.warn('[init setLlmUi]', e);
    }
    try {
      bindFile();
    } catch (e) {
      console.warn('[init bindFile]', e);
    }
    try {
      setFileUiState('idle');
      syncInputSourceUI();
      renderTable();
      renderTopStats();
      renderAnalysis();
    } catch (e) {
      console.warn('[init render]', e);
    }

    try {
      $('btnLlmMapToggle')?.addEventListener('click', () => {
        state.llmMapEnabled = !state.llmMapEnabled;
        setLlmUi();
      });
      $('btnLlmAnalyzeToggle')?.addEventListener('click', () => {
        state.llmAnalyzeEnabled = !state.llmAnalyzeEnabled;
        setLlmUi();
      });
      $('btnMap')?.addEventListener('click', () => {
        doMap().catch((e) => {
          console.error('[map click]', e);
          alert(e.message || String(e));
        });
      });
      wireAnalyzeButton();
    } catch (e) {
      console.warn('[init bind buttons]', e);
    }

    try {
      const rules = await api('/mapping/rules');
      if (Array.isArray(rules.iocDisplayColumns) && rules.iocDisplayColumns.length) {
        state.iocColumns = rules.iocDisplayColumns;
        renderTableHead();
      }
    } catch (_) {
      
    }

    $('btnSave')?.addEventListener('click', () => doPersist('intels'));
    $('btnSaveStats')?.addEventListener('click', () => doPersist('stats'));
    $('btnPickSample')?.addEventListener('click', openSamples);
    $('detailClose')?.addEventListener('click', () => ($('detailModal').hidden = true));
    $('sampleClose')?.addEventListener('click', closeSampleModal);
    $('sampleCancel')?.addEventListener('click', closeSampleModal);
    $('sampleConfirm')?.addEventListener('click', confirmSample);
    $('detailModal')?.addEventListener('click', (e) => {
      if (e.target === $('detailModal')) $('detailModal').hidden = true;
    });
    $('sampleModal')?.addEventListener('click', (e) => {
      if (e.target === $('sampleModal')) closeSampleModal();
    });
    $('resultBody')?.addEventListener('click', (e) => {
      const tr = e.target.closest('tr[data-idx]');
      if (!tr) return;
      openDetail(Number(tr.dataset.idx));
    });
    $('sampleList')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-key]');
      if (btn) previewSample(btn.dataset.key);
    });

    try {
      const health = await api('/health');
      const pill = $('apiStatus');
      pill.textContent = health.mongo ? 'API · Mongo 已连接' : 'API · 内存模式';
      pill.classList.add('ok');
    } catch (_) {
      $('apiStatus').textContent = 'API 不可用';
      $('apiStatus').classList.add('err');
    }
    await refreshCumulative();
    try {
      const tac = await api('/attck/tactics');
      state.coverage = (tac.killChainOrder || []).map((t) => ({ ...t, count: 0, techniques: {} }));
      renderCoverage();
    } catch (_) {
      
    }
  }

  function startApp() {
    init().catch((e) => {
      console.error('[init]', e);
      
    });
  }

  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startApp);
  } else {
    startApp();
  }
})();
