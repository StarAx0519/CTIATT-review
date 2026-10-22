const mongoose = require('mongoose');

const MappedIntelSchema = new mongoose.Schema(
  {
    batchId: { type: String, index: true },
    
    sourceId: { type: String, index: true },
    itemHash: { type: String, index: true },
    contentHash: { type: String, index: true },
    title: String,
    description: String,
    threatType: String,
    tags: [String],
    source: String,
    timestamp: mongoose.Schema.Types.Mixed,
    iocs: [mongoose.Schema.Types.Mixed],
    iocSummary: mongoose.Schema.Types.Mixed,
    iocColumns: mongoose.Schema.Types.Mixed,
    mapping: mongoose.Schema.Types.Mixed,
    techniqueMappings: [mongoose.Schema.Types.Mixed],
    techniqueIds: [String],
    rawTechniqueIds: [String],
    techniqueCount: Number,
    llmAssisted: Boolean,
    vectorAssisted: Boolean,
    analysisSnippet: String,
    raw: mongoose.Schema.Types.Mixed
  },
  { timestamps: true, collection: 'mappedintels' }
);

const SessionStatsSchema = new mongoose.Schema(
  {
    batchId: { type: String, unique: true },
    stats: mongoose.Schema.Types.Mixed,
    coverage: mongoose.Schema.Types.Mixed,
    analysis: String,
    llmEnabled: Boolean
  },
  { timestamps: true, collection: 'sessionstats' }
);

const SampleIntelSchema = new mongoose.Schema(
  {
    sampleKey: { type: String, unique: true },
    name: String,
    description: String,
    format: String,
    content: String
  },
  { timestamps: true, collection: 'sampleintels' }
);

const MappedIntel = mongoose.models.MappedIntel || mongoose.model('MappedIntel', MappedIntelSchema);
const SessionStats = mongoose.models.SessionStats || mongoose.model('SessionStats', SessionStatsSchema);
const SampleIntel = mongoose.models.SampleIntel || mongoose.model('SampleIntel', SampleIntelSchema);

module.exports = { MappedIntel, SessionStats, SampleIntel };
