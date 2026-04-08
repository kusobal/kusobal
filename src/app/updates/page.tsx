'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

interface Update {
  _id: string;
  productType: 'ESXi' | 'vCenter' | 'Veeam' | 'iDRAC' | 'iLO' | 'BIOS';
  vendor: 'Broadcom' | 'VMware' | 'Veeam' | 'Dell' | 'HP';
  version: string;
  patch: string;
  releaseDate: string;
  category: 'Security' | 'Bug Fix' | 'Feature' | 'Performance' | 'Stability';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  releaseNotesEN: string;
  releaseNotesTR: string;
  url?: string;
}

const productTypeColors: Record<string, string> = {
  ESXi: 'bg-purple-100 text-purple-800',
  vCenter: 'bg-blue-100 text-blue-800',
  Veeam: 'bg-green-100 text-green-800',
  iDRAC: 'bg-red-100 text-red-800',
  iLO: 'bg-orange-100 text-orange-800',
  BIOS: 'bg-yellow-100 text-yellow-800',
};

const severityColors: Record<string, string> = {
  Critical: 'text-red-600 bg-red-50',
  High: 'text-orange-600 bg-orange-50',
  Medium: 'text-yellow-600 bg-yellow-50',
  Low: 'text-green-600 bg-green-50',
};

const severityIcons: Record<string, string> = {
  Critical: '🔴',
  High: '🟠',
  Medium: '🟡',
  Low: '🟢',
};

export default function UpdatesPage() {
  const router = useRouter();
  const [updates, setUpdates] = useState<Update[]>([]);
  const [filteredUpdates, setFilteredUpdates] = useState<Update[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedUpdate, setSelectedUpdate] = useState<Update | null>(null);
  const [language, setLanguage] = useState<'EN' | 'TR'>('EN');

  const [filters, setFilters] = useState({
    productType: '',
  });

  useEffect(() => {
    fetchUpdates();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [updates, filters]);

  const fetchUpdates = async () => {
    try {
      const response = await fetch('/api/updates?limit=1000&sortBy=releaseDate');
      if (response.ok) {
        const data = await response.json();
        setUpdates(data.sort((a: Update, b: Update) => 
          new Date(b.releaseDate).getTime() - new Date(a.releaseDate).getTime()
        ));
      }
    } catch (error) {
      console.error('Error fetching updates:', error);
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = updates;

    if (filters.productType) {
      filtered = filtered.filter(u => u.productType === filters.productType);
    }

    setFilteredUpdates(filtered);
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('tr-TR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  const productTypes = Array.from(new Set(updates.map(u => u.productType)));

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 flex items-center justify-center">
        <div className="text-gray-700 text-xl">Güncellemeler yükleniyor...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 text-white sticky top-0 z-50 shadow-xl">
        <div className="max-w-7xl mx-auto px-8 py-6">
          <button type="button" onClick={() => router.push('/')} className="text-sm font-semibold text-indigo-100 hover:text-white mb-4 flex items-center gap-2 transition-colors">
            ← Anasayfa
          </button>
          <h1 className="text-4xl font-black text-white mb-1">📦 Güncellemeler</h1>
          <p className="text-indigo-100 text-lg">Tüm yazılım ve firmware güncellemelerini takip edin</p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-8 py-12">
        {/* Filters */}
        <div className="bg-gradient-to-br from-white to-slate-50 rounded-2xl shadow-lg p-8 mb-12 border border-indigo-300 backdrop-blur-sm">
          <h2 className="text-xl font-bold text-gray-900 mb-6">Filtreler</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-bold text-gray-700 mb-3">Ürün Tipi</label>
              <select
                value={filters.productType}
                onChange={(e) => setFilters({ ...filters, productType: e.target.value })}
                className="w-full px-4 py-3 border border-indigo-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white/90 text-gray-900 backdrop-blur-sm"
              >
                <option value="">Tümü</option>
                {productTypes.map(pt => (
                  <option key={pt} value={pt}>{pt}</option>
                ))}
              </select>
            </div>

            <div className="flex items-end">
              <button
                onClick={() => setFilters({ productType: '' })}
                className="w-full px-4 py-3 bg-gradient-to-r from-slate-400 to-slate-500 hover:from-slate-500 hover:to-slate-600 text-white font-semibold rounded-lg transition-all"
              >
                Sıfırla
              </button>
            </div>
          </div>
        </div>

        {/* Updates List */}
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-6">
            {filteredUpdates.length} Güncelleme
          </h2>

          {filteredUpdates.length === 0 ? (
            <div className="bg-gradient-to-br from-white to-slate-50 rounded-2xl shadow-md p-12 text-center border border-indigo-300 backdrop-blur-sm">
              <p className="text-xl text-gray-500 font-medium">Güncelleme bulunamadı</p>
              <p className="text-gray-400 mt-2">Farklı filtreler deneyin</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredUpdates.map((update) => (
                <div
                  key={update._id}
                  onClick={() => setSelectedUpdate(update)}
                  className="bg-gradient-to-br from-white to-slate-50 rounded-2xl shadow-md hover:shadow-lg p-6 border border-indigo-300 hover:border-purple-400 cursor-pointer transition-all backdrop-blur-sm"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${productTypeColors[update.productType] || 'bg-gray-100 text-gray-800'}`}>
                          {update.productType}
                        </span>
                        <span className="text-xs font-semibold text-gray-500">{update.vendor}</span>
                        <span className={`text-xs font-bold ${severityColors[update.severity]}`}>
                          {severityIcons[update.severity]} {update.severity}
                        </span>
                      </div>
                      <h3 className="text-lg font-bold text-gray-900 mb-2">
                        {update.productType} {update.version} - {update.patch}
                      </h3>
                      <div className="flex items-center gap-4">
                        <span className="text-sm text-gray-600">
                          📅 {formatDate(update.releaseDate)}
                        </span>
                        <span className="text-sm text-gray-600">
                          🏷️ {update.category}
                        </span>
                      </div>
                    </div>
                    <div className="text-right text-indigo-600 font-bold">
                      Detaylar →
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detail Modal */}
      {selectedUpdate && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4 backdrop-blur-lg animate-fadeIn">
          <div className="bg-gradient-to-br from-white via-indigo-50 to-purple-50 rounded-3xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-indigo-400 animate-slideUp">
            {/* Modal Header */}
            <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 px-8 py-6 flex items-center justify-between sticky top-0">
              <div>
                <h2 className="text-2xl font-bold text-white mb-2">
                  {selectedUpdate.productType} {selectedUpdate.version}
                </h2>
                <p className="text-indigo-100">
                  Patch: {selectedUpdate.patch} • {formatDate(selectedUpdate.releaseDate)}
                </p>
              </div>
              <button
                onClick={() => setSelectedUpdate(null)}
                className="text-white hover:bg-white/20 p-2 rounded-lg transition-all text-2xl"
              >
                ✕
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-8">
              {/* Meta Info */}
              <div className="grid grid-cols-4 gap-4 mb-8 pb-8 border-b-2 border-slate-200">
                <div className="bg-gradient-to-br from-slate-100 to-slate-50 p-4 rounded-xl border border-slate-200 hover:border-slate-300 transition-all">
                  <p className="text-xs text-gray-600 font-bold uppercase mb-2 tracking-wider">Vendor</p>
                  <p className="text-lg font-bold text-gray-900">{selectedUpdate.vendor}</p>
                </div>
                <div className="bg-gradient-to-br from-blue-100 to-blue-50 p-4 rounded-xl border border-blue-200 hover:border-blue-300 transition-all">
                  <p className="text-xs text-blue-600 font-bold uppercase mb-2 tracking-wider">Kategori</p>
                  <p className="text-lg font-bold text-blue-900">{selectedUpdate.category}</p>
                </div>
                <div className={`bg-gradient-to-br p-4 rounded-xl border-2 transition-all ${
                  selectedUpdate.severity === 'Critical' ? 'from-red-100 to-red-50 border-red-300' :
                  selectedUpdate.severity === 'High' ? 'from-orange-100 to-orange-50 border-orange-300' :
                  selectedUpdate.severity === 'Medium' ? 'from-yellow-100 to-yellow-50 border-yellow-300' :
                  'from-green-100 to-green-50 border-green-300'
                }`}>
                  <p className="text-xs font-bold uppercase mb-2 tracking-wider" style={{
                    color: selectedUpdate.severity === 'Critical' ? '#991B1B' :
                           selectedUpdate.severity === 'High' ? '#92400E' :
                           selectedUpdate.severity === 'Medium' ? '#854D0E' :
                           '#166534'
                  }}>Önem Derecesi</p>
                  <p className={`text-lg font-bold ${severityColors[selectedUpdate.severity]}`}>
                    {severityIcons[selectedUpdate.severity]} {selectedUpdate.severity}
                  </p>
                </div>
                <div className="bg-gradient-to-br from-indigo-100 to-indigo-50 p-4 rounded-xl border border-indigo-200 hover:border-indigo-300 transition-all">
                  <p className="text-xs text-indigo-600 font-bold uppercase mb-2 tracking-wider">Tarih</p>
                  <p className="text-lg font-bold text-indigo-900">{formatDate(selectedUpdate.releaseDate)}</p>
                </div>
              </div>

              {/* Language Tabs */}
              <div className="flex gap-2 mb-6 border-b border-slate-200">
                <button
                  onClick={() => setLanguage('TR')}
                  className={`px-6 py-3 font-bold transition-all border-b-2 ${
                    language === 'TR'
                      ? 'text-indigo-600 border-indigo-600'
                      : 'text-gray-500 border-transparent hover:text-gray-900'
                  }`}
                >
                  🇹🇷 Türkçe
                </button>
                <button
                  onClick={() => setLanguage('EN')}
                  className={`px-6 py-3 font-bold transition-all border-b-2 ${
                    language === 'EN'
                      ? 'text-indigo-600 border-indigo-600'
                      : 'text-gray-500 border-transparent hover:text-gray-900'
                  }`}
                >
                  🇬🇧 English
                </button>
              </div>

              {/* Release Notes */}
              <div className="prose prose-sm max-w-none">
                <div className="whitespace-pre-wrap text-gray-700 leading-relaxed bg-gradient-to-br from-slate-100 via-blue-50 to-indigo-50 p-8 rounded-2xl border-2 border-slate-200 shadow-md hover:shadow-lg transition-shadow">
                  {language === 'TR' ? selectedUpdate.releaseNotesTR : selectedUpdate.releaseNotesEN}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="bg-gradient-to-r from-slate-50 to-indigo-50 px-8 py-4 border-t border-indigo-300 flex justify-end">
              <button
                onClick={() => setSelectedUpdate(null)}
                className="px-6 py-2 bg-gradient-to-r from-slate-400 to-slate-500 hover:from-slate-500 hover:to-slate-600 text-white font-bold rounded-lg transition-all"
              >
                Kapat
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
