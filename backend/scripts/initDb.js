const mongoose = require('mongoose');
const config = require('../src/config');
const { MappedIntel, SessionStats, SampleIntel } = require('../src/models');

const samples = [
  {
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
            description:
              'Info stealer harvesting browser credentials and exfiltrating via HTTPS',
            labels: ['info-stealer']
          }
        ]
      },
      null,
      2
    )
  },
  {
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

async function main() {
  const uri = config.mongoUri;
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 8000 });
  console.log('Connected:', uri);

  await MappedIntel.createCollection();
  await SessionStats.createCollection();
  await SampleIntel.createCollection();

  await MappedIntel.collection.createIndex({ batchId: 1 });
  await MappedIntel.collection.createIndex({ sourceId: 1 });
  await MappedIntel.collection.createIndex({ itemHash: 1 });
  await MappedIntel.collection.createIndex({ contentHash: 1 });
  await SessionStats.collection.createIndex({ batchId: 1 }, { unique: true });
  await SampleIntel.collection.createIndex({ sampleKey: 1 }, { unique: true });

  for (const s of samples) {
    await SampleIntel.findOneAndUpdate(
      { sampleKey: s.sampleKey },
      { $set: s },
      { upsert: true, new: true }
    );
  }

  console.log('Database initialized: mappedintels / sessionstats / sampleintels');
  console.log(`Sample intels upserted: ${samples.length}`);
  await mongoose.disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
