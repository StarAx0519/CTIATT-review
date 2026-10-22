require('./src/config');

const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const config = require('./src/config');
const { loadAttckData, getDefaultAttckPath } = require('./src/attckParser');
const { loadMappingKnowledge } = require('./src/knowledgeLoader');

loadMappingKnowledge();

const { createRouter } = require('./src/routes');

const PORT = config.port;
const MONGO_URI = config.mongoUri;

const attckPath = process.env.ATTCK_PATH || getDefaultAttckPath();
if (!fs.existsSync(attckPath)) {
  console.error('[启动失败] 找不到 ATTCK.json:', attckPath);
  process.exit(1);
}

const attck = loadAttckData(attckPath);
console.log(
  `[ATT&CK] ${attck.tactics.length} tactics, ${attck.techniques.length} techniques ← ${attckPath}`
);

const app = express();
app.use(cors());
app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: true, limit: '8mb' }));
app.use('/api', createRouter(attck));

const frontendDir = path.join(__dirname, '..', 'frontend');
if (!fs.existsSync(frontendDir)) {
  console.warn('[警告] 前端目录不存在:', frontendDir);
} else {
  app.use(express.static(frontendDir));
  app.get(['/', '/index.html'], (_req, res) => {
    res.sendFile(path.join(frontendDir, 'index.html'));
  });
}

async function main() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
    console.log(`[MongoDB] connected ← ${MONGO_URI}`);
  } catch (e) {
    console.warn(`[MongoDB] 未连接（映射仍可用，入库不可用）: ${e.message}`);
  }

  const server = app.listen(PORT, () => {
    console.log(`[QY ThreatIntel] http://127.0.0.1:${PORT}`);
  });

  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      console.error(
        `[启动失败] 端口 ${PORT} 已被占用。请关闭占用该端口的进程后重试，或修改 .env 中的 PORT。`
      );
      process.exit(1);
    }
    console.error('[启动失败]', err);
    process.exit(1);
  });
}

main().catch((e) => {
  console.error('[启动失败]', e);
  process.exit(1);
});
