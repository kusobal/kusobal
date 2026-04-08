import mongoose from 'mongoose';

const PatchReleaseSchema = new mongoose.Schema({
  product: { type: String, required: true },
  version: { type: String, required: true }, // e.g., '8.0 Update 3'
  releaseDate: { type: Date, required: true },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.models.PatchRelease || mongoose.model('PatchRelease', PatchReleaseSchema);