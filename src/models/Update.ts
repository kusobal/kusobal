import mongoose from 'mongoose';

const UpdateSchema = new mongoose.Schema({
  productType: { 
    type: String, 
    enum: ['ESXi', 'vCenter', 'Veeam', 'iDRAC', 'iLO', 'BIOS'],
    required: true 
  },
  vendor: { 
    type: String, 
    enum: ['Broadcom', 'VMware', 'Veeam', 'Dell', 'HP'],
    required: true 
  },
  version: { 
    type: String, 
    required: true 
  },
  patch: { 
    type: String, 
    required: true 
  },
  releaseDate: { 
    type: Date, 
    required: true 
  },
  category: { 
    type: String, 
    enum: ['Security', 'Bug Fix', 'Feature', 'Performance', 'Stability'],
    default: 'Bug Fix'
  },
  releaseNotesEN: { 
    type: String, 
    required: true 
  },
  releaseNotesTR: { 
    type: String, 
    required: true 
  },
  url: { 
    type: String, 
    required: false 
  },
  severity: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Medium'
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  },
});

export default mongoose.models.Update || mongoose.model('Update', UpdateSchema);
