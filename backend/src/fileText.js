const path = require('path');
const { recoverCtiJsonText } = require('./ctiRecover');
const { undefangText } = require('./iocExtract');

function isPdfUpload(file) {
  if (!file) return false;
  const name = String(file.originalname || '').toLowerCase();
  const mime = String(file.mimetype || '').toLowerCase();
  return mime.includes('pdf') || name.endsWith('.pdf');
}

function isHtmlUpload(file) {
  if (!file) return false;
  const name = String(file.originalname || '').toLowerCase();
  const mime = String(file.mimetype || '').toLowerCase();
  return (
    name.endsWith('.html') ||
    name.endsWith('.htm') ||
    mime.includes('text/html')
  );
}

function isMhtmlUpload(file) {
  if (!file) return false;
  const name = String(file.originalname || '').toLowerCase();
  const mime = String(file.mimetype || '').toLowerCase();
  return (
    name.endsWith('.mhtml') ||
    name.endsWith('.mht') ||
    name.endsWith('.eml') ||
    mime.includes('multipart/related') ||
    mime.includes('message/rfc822')
  );
}

function titleFromUpload(file, fallback) {
  const base = path.basename(file?.originalname || fallback || 'upload');
  const ext = path.extname(base);
  return ext ? base.slice(0, -ext.length) : base;
}

function bufferToText(buf) {
  if (!Buffer.isBuffer(buf) || !buf.length) return '';
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.slice(2).toString('utf16le');
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    
    const swapped = Buffer.alloc(buf.length - 2);
    for (let i = 2; i + 1 < buf.length; i += 2) {
      swapped[i - 2] = buf[i + 1];
      swapped[i - 1] = buf[i];
    }
    return swapped.toString('utf16le');
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.slice(3).toString('utf8');
  }
  return buf.toString('utf8');
}

function itemsToText(items) {
  if (!items?.length) return '';
  const enriched = items
    .map((it) => {
      const str = typeof it.str === 'string' ? it.str : '';
      const tr = it.transform || [1, 0, 0, 1, 0, 0];
      const x = Number(tr[4]) || 0;
      const y = Number(tr[5]) || 0;
      return { str, x, y };
    })
    .filter((it) => it.str);

  enriched.sort((a, b) => {
    const dy = b.y - a.y;
    if (Math.abs(dy) > 2.5) return dy;
    return a.x - b.x;
  });

  const lines = [];
  let cur = [];
  let lastY = null;
  for (const it of enriched) {
    if (lastY == null || Math.abs(it.y - lastY) <= 2.5) {
      cur.push(it);
    } else {
      lines.push(joinLineItems(cur));
      cur = [it];
    }
    lastY = it.y;
  }
  if (cur.length) lines.push(joinLineItems(cur));
  return lines.filter(Boolean).join('\n').trim();
}

function joinLineItems(items) {
  if (!items.length) return '';
  let out = items[0].str;
  for (let i = 1; i < items.length; i++) {
    const prev = items[i - 1];
    const cur = items[i];
    const gap = cur.x - prev.x;
    if (gap > 1.2) out += ' ';
    out += cur.str;
  }
  return out.replace(/[ \t]+/g, ' ').trim();
}

async function extractWithPdfJs(buffer) {
  let pdfjs;
  try {
    pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
  } catch (_) {
    const err = new Error('服务端未安装 pdfjs-dist，无法解析 PDF');
    err.status = 500;
    throw err;
  }
  try {
    const loadingTask = pdfjs.getDocument({
      data: new Uint8Array(buffer),
      useSystemFonts: true,
      disableWorker: true
    });
    const pdf = await loadingTask.promise;
    const parts = [];
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const content = await page.getTextContent();
      const pageText = itemsToText(content.items || []);
      if (pageText) parts.push(pageText);
    }
    return parts.join('\n').trim();
  } catch (e) {
    const err = new Error(`PDF 解析失败: ${e.message}`);
    err.status = 400;
    throw err;
  }
}

function decodeHtmlEntities(s) {
  return String(s || '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)));
}

function htmlToText(html) {
  let s = String(html || '');
  s = s.replace(/<script[\s\S]*?<\/script>/gi, ' ');
  s = s.replace(/<style[\s\S]*?<\/style>/gi, ' ');
  s = s.replace(/<!--[\s\S]*?-->/g, ' ');
  s = s.replace(/<\/(p|div|br|li|tr|h[1-6]|section|article)>/gi, '\n');
  s = s.replace(/<(br|hr)\s*\/?>/gi, '\n');
  s = s.replace(/<[^>]+>/g, ' ');
  s = decodeHtmlEntities(s);
  s = s.replace(/\r\n/g, '\n').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n');
  s = s.replace(/[ \t]{2,}/g, ' ');
  return s.trim();
}

function extractMhtmlHtml(raw) {
  const text = String(raw || '');
  
  const parts = text.split(/\r?\n------=_?(?:NextPart|Part)[^\r\n]*/i);
  let best = '';
  const pushCandidate = (body) => {
    const b = String(body || '').trim();
    if (b.length > best.length) best = b;
  };

  if (parts.length <= 1) {
    
    const m = text.match(/<html[\s\S]*<\/html>/i);
    if (m) return m[0];
    return text;
  }

  for (const part of parts) {
    const headerEnd = part.search(/\r?\n\r?\n/);
    if (headerEnd < 0) continue;
    const headers = part.slice(0, headerEnd);
    let body = part.slice(headerEnd).replace(/^\r?\n\r?\n/, '');
    const ct = /Content-Type:\s*([^\r\n;]+)/i.exec(headers);
    const te = /Content-Transfer-Encoding:\s*([^\r\n]+)/i.exec(headers);
    const type = (ct && ct[1].trim().toLowerCase()) || '';
    if (type && !type.includes('text/html') && !type.includes('text/plain')) continue;
    const enc = (te && te[1].trim().toLowerCase()) || '';
    if (enc.includes('base64')) {
      try {
        const cleaned = body.replace(/\s+/g, '');
        body = Buffer.from(cleaned, 'base64').toString('utf8');
      } catch (_) {
        continue;
      }
    } else if (enc.includes('quoted-printable')) {
      
      const qp = body.replace(/=\r?\n/g, '');
      const bytes = [];
      for (let i = 0; i < qp.length; i++) {
        if (qp[i] === '=' && /^[0-9A-Fa-f]{2}/.test(qp.slice(i + 1, i + 3))) {
          bytes.push(parseInt(qp.slice(i + 1, i + 3), 16));
          i += 2;
        } else {
          bytes.push(qp.charCodeAt(i) & 0xff);
        }
      }
      body = Buffer.from(bytes).toString('utf8');
    }
    if (type.includes('text/html') || /<html[\s\S]*<\/html>/i.test(body)) {
      pushCandidate(body);
    } else if (type.includes('text/plain')) {
      pushCandidate(body);
    }
  }

  if (best) return best;
  const m = text.match(/<html[\s\S]*<\/html>/i);
  return m ? m[0] : text.slice(0, 2_000_000);
}

function wrapNarrative(kind, titleHint, body) {
  const text = undefangText(body);
  const recovered = recoverCtiJsonText(text);
  if (recovered) return recovered;
  return `${kind}威胁情报报告: ${titleHint}\n\n${text}`;
}

async function extractFileText(file) {
  if (!file?.buffer) return '';

  if (isPdfUpload(file)) {
    const text = await extractWithPdfJs(file.buffer);
    if (!text) {
      const err = new Error('PDF 未能提取到有效文本（可能为扫描件/纯图片 PDF）');
      err.status = 400;
      throw err;
    }
    const titleHint = titleFromUpload(file, 'document.pdf');
    return wrapNarrative('PDF ', titleHint, text);
  }

  if (isMhtmlUpload(file)) {
    const raw = bufferToText(file.buffer);
    const html = extractMhtmlHtml(raw);
    const text = htmlToText(html);
    if (!text || text.length < 40) {
      const err = new Error('MHTML/EML 未能提取到有效正文');
      err.status = 400;
      throw err;
    }
    const titleHint = titleFromUpload(file, 'document.mhtml');
    
    const clipped = text.length > 400_000 ? text.slice(0, 400_000) : text;
    const kind = String(file.originalname || '').toLowerCase().endsWith('.eml') ? 'EML ' : 'MHTML ';
    return wrapNarrative(kind, titleHint, clipped);
  }

  if (isHtmlUpload(file)) {
    const raw = bufferToText(file.buffer);
    const text = htmlToText(raw);
    if (!text || text.length < 20) {
      const err = new Error('HTML 未能提取到有效正文');
      err.status = 400;
      throw err;
    }
    const titleHint = titleFromUpload(file, 'document.html');
    const clipped = text.length > 400_000 ? text.slice(0, 400_000) : text;
    return wrapNarrative('HTML ', titleHint, clipped);
  }

  
  const raw = bufferToText(file.buffer);
  const recovered = recoverCtiJsonText(raw);
  if (recovered) return recovered;
  
  if (/<html[\s>]/i.test(raw) || /<!DOCTYPE html/i.test(raw)) {
    const text = htmlToText(raw);
    if (text && text.length >= 20) {
      return wrapNarrative('HTML ', titleFromUpload(file, 'document'), text.slice(0, 400_000));
    }
  }
  return undefangText(raw);
}

async function parseBodyInputAsync(req) {
  let text = '';
  if (req.file?.buffer) {
    text = await extractFileText(req.file);
  }
  if (req.body?.text) {
    const paste = String(req.body.text);
    text = text ? `${text}\n${paste}` : paste;
  }
  return text;
}

module.exports = {
  isPdfUpload,
  isHtmlUpload,
  isMhtmlUpload,
  extractFileText,
  parseBodyInputAsync,
  itemsToText,
  htmlToText,
  extractMhtmlHtml,
  bufferToText,
  titleFromUpload
};
