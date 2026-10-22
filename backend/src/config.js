const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '../../.env') });
dotenv.config({ path: path.join(__dirname, '../.env') });

function env(name, fallback = '') {
  const v = process.env[name];
  return v == null || v === '' ? fallback : v;
}

function envInt(name, fallback) {
  const n = Number(env(name, String(fallback)));
  return Number.isFinite(n) ? n : fallback;
}

const openieLlm = {
  apiKey: env('OPENIE_LLM_API_KEY'),
  baseUrl: env('OPENIE_LLM_BASE_URL', 'https://api.deepseek.com/v1').replace(/\/$/, ''),
  model: env('OPENIE_LLM_MODEL', 'deepseek-chat')
};

const chatLlm = {
  apiKey: env('CHAT_LLM_API_KEY') || openieLlm.apiKey,
  baseUrl: env('CHAT_LLM_BASE_URL', openieLlm.baseUrl).replace(/\/$/, ''),
  model: env('CHAT_LLM_MODEL', openieLlm.model)
};

const vector = {
  apiKey: env('VECTOR_API_KEY'),
  baseUrl: env('VECTOR_BASE_URL', 'https://api.siliconflow.cn/v1').replace(/\/$/, ''),
  model: env('VECTOR_MODEL', 'BAAI/bge-m3')
};

const config = {
  port: envInt('PORT', 3100),
  mongoUri: env('MONGO_URI', 'mongodb://127.0.0.1:27017/qy_threat_intel'),
  mappingKnowledgePath: env('MAPPING_KNOWLEDGE_PATH', ''),
  openieLlm,
  chatLlm,
  vector,
  get llmReady() {
    return Boolean(openieLlm.apiKey && openieLlm.baseUrl && openieLlm.model);
  },
  get vectorReady() {
    return Boolean(vector.apiKey && vector.baseUrl && vector.model);
  }
};

module.exports = config;
