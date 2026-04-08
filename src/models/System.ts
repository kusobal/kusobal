import mongoose from 'mongoose';

const SystemSchema = new mongoose.Schema({
  customer: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
  name: { type: String, required: true },
  category: { type: String, required: true },
  subCategory: { type: String, required: true },
  model: { type: String, required: true },
  bios: { type: String, required: true },
  idrac: { type: String, required: true },
  esxiVersion: { 
    type: String, 
    required: function(this: any) { return this.category === 'Dell' || this.category === 'HP'; },
    default: null
  },
  esxiPatch: { 
    type: String, 
    required: function(this: any) { return this.category === 'Dell' || this.category === 'HP'; },
    default: null
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

export default mongoose.models.System || mongoose.model('System', SystemSchema);