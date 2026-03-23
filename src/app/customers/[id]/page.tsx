'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter, useParams } from 'next/navigation';
import { products } from '@/lib/products';

interface System {
  _id: string;
  name: string;
  category: string;
  subCategory: string;
  model: string;
  bios: string;
  idrac: string;
  esxiVersion?: string;
  esxiPatch?: string;
}

interface Customer {
  _id: string;
  name: string;
}

const categories = Object.keys(products) as (keyof typeof products)[];

export default function CustomerDetail() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const { id } = useParams();
  const [customer, setCustomer] = useState<Customer | null>(null);
  const [systems, setSystems] = useState<System[]>([]);
  const [category, setCategory] = useState<keyof typeof products | ''>('' as const);
  const [subCategory, setSubCategory] = useState('');
  const [model, setModel] = useState('');
  const [bios, setBios] = useState('');
  const [idrac, setIdrac] = useState('');
  const [systemName, setSystemName] = useState('');
  const [esxiVersion, setEsxiVersion] = useState('');
  const [esxiPatch, setEsxiPatch] = useState('');
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);

  const subCategories: string[] = category === 'vCenter' ? [] : (category ? Object.keys(products[category as keyof typeof products]): []);
  const models: string[] = category === 'vCenter' 
    ? (products.vCenter as any) || []
    : (category && subCategory && category !== 'Veeam'
      ? Object.keys((products[category as keyof typeof products] as any)[subCategory]).filter(key => !Array.isArray((products[category as keyof typeof products] as any)[subCategory][key]) && key !== 'bios' && key !== 'idrac' && key !== 'ilo' && key !== 'versions')
      : []);
  
  const veeamVersions: string[] = category === 'Veeam' && subCategory 
    ? ((products[category as keyof typeof products] as any)[subCategory] || [])
    : [];
  
  const biosList: string[] = category && subCategory && model && category !== 'Veeam'
    ? ((products[category as keyof typeof products] as any)[subCategory][model])?.bios || []
    : [];
  
  const idracList: string[] = category && subCategory && model && category !== 'Veeam'
    ? ((products[category as keyof typeof products] as any)[subCategory][model])?.idrac || 
      ((products[category as keyof typeof products] as any)[subCategory][model])?.ilo || []
    : [];

  const esxiVersions: string[] = category === 'Dell' || category === 'HP' ? Object.keys((products as any).esxiVersions || {}) : [];
  const esxiPatches: string[] = (esxiVersion && (category === 'Dell' || category === 'HP')) 
    ? ((products as any).esxiVersions?.[esxiVersion] || [])
    : [];

  useEffect(() => {
    if (status === 'loading') return;
    if (!session) {
      router.push('/auth/signin');
    } else {
      fetchCustomer();
      fetchSystems();
    }
  }, [session, status, router, id]);

  const fetchCustomer = async () => {
    const res = await fetch(`/api/customers/${id}`);
    if (res.ok) {
      const data = await res.json();
      setCustomer(data);
    }
  };

  const fetchSystems = async () => {
    const res = await fetch(`/api/customers/${id}/systems`);
    if (res.ok) {
      const data = await res.json();
      setSystems(data);
    }
    setLoading(false);
  };

  const handleEdit = (system: System) => {
    setEditingId(system._id);
    setSystemName(system.name);
    setCategory(system.category as keyof typeof products);
    setSubCategory(system.category === 'vCenter' ? '' : system.subCategory);
    setModel(system.category === 'Veeam' || system.category === 'vCenter' ? '' : system.model);
    setBios(system.category === 'Veeam' ? '' : system.bios);
    setIdrac(system.category === 'Veeam' ? '' : system.idrac);
    setEsxiVersion(system.esxiVersion || '');
    setEsxiPatch(system.esxiPatch || '');
  };

  const handleCancelEdit = () => {
    setEditingId(null);
    setSystemName('');
    setCategory('');
    setSubCategory('');
    setModel('');
    setBios('');
    setIdrac('');
    setEsxiVersion('');
    setEsxiPatch('');
  };

  const addOrUpdateSystem = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const body: any = { name: systemName, category };
    
    if (category !== 'vCenter') {
      body.subCategory = subCategory;
    }
    
    if (category !== 'Veeam' && category !== 'vCenter') {
      body.model = model;
      body.bios = bios;
      body.idrac = idrac;
    }
    
    if (category === 'vCenter') {
      body.model = model;
    }
    
    if (category === 'Dell' || category === 'HP') {
      body.esxiVersion = esxiVersion;
      body.esxiPatch = esxiPatch;
    }

    const url = editingId ? `/api/systems/${editingId}` : '/api/systems';
    const method = editingId ? 'PUT' : 'POST';

    const payload = editingId ? body : { customerId: id, ...body };

    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      handleCancelEdit();
      fetchSystems();
    } else {
      const error = await res.json();
      alert('Hata: ' + (error.error || 'Sistem kaydedilirken hata oluştu'));
    }
  };

  const deleteSystem = async (systemId: string) => {
    if (!confirm('Bu sistemi silmek istediğinize emin misiniz?')) return;
    
    const res = await fetch(`/api/systems/${systemId}`, { method: 'DELETE' });
    if (res.ok) {
      fetchSystems();
    }
  };

  if (status === 'loading' || loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 flex items-center justify-center">
        <div className="text-gray-700 text-xl">Yükleniyor...</div>
      </div>
    );
  }

  if (!customer) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 flex items-center justify-center">
        <div className="text-gray-700 text-xl">Müşteri bulunamadı</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 sticky top-0 z-50 text-white shadow-xl">
        <div className="max-w-7xl mx-auto px-8 py-6">
          <button onClick={() => router.push('/customers')} className="text-sm font-semibold text-indigo-100 hover:text-white mb-4 flex items-center gap-2 transition-colors">
            <span>←</span> Müşteriler
          </button>
          <h1 className="text-4xl font-black text-white mb-1">{customer.name}</h1>
          <p className="text-indigo-100 text-lg">Sunucu ve Bilgisayar Yönetimi Paneli</p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-8 py-12">
        {/* Form Section */}
        <div className="bg-white rounded-2xl shadow-lg p-12 mb-16 border border-slate-200">
          <div className="mb-10">
            <h2 className="text-3xl font-bold text-gray-900 mb-2">
              {editingId ? 'Sistem Düzenle' : 'Yeni Sistem Ekle'}
            </h2>
            <p className="text-slate-500">Sunucu ve bilgisayar bilgilerini yönetin</p>
          </div>
          
          <form onSubmit={addOrUpdateSystem} className="space-y-8">
            <div>
              <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Sistem Adı *</label>
              <input
                type="text"
                value={systemName}
                onChange={(e) => setSystemName(e.target.value)}
                placeholder="Örn: YılmazProd1, ÜretimSunucuA"
                className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all placeholder-gray-400 bg-white text-gray-900"
                required
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div>
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Kategori *</label>
                <select
                  value={category}
                  onChange={(e) => {
                    setCategory(e.target.value as keyof typeof products);
                    setSubCategory('');
                    setModel('');
                    setBios('');
                    setIdrac('');
                    setEsxiVersion('');
                    setEsxiPatch('');
                  }}
                  className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                  required
                >
                  <option value="">Seçin</option>
                  {categories.map((cat) => (
                    <option key={cat} value={cat}>{cat}</option>
                  ))}
                </select>
              </div>

              {category && category !== 'vCenter' && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Alt Kategori *</label>
                  <select
                    value={subCategory}
                    onChange={(e) => {
                      setSubCategory(e.target.value);
                      setModel('');
                      setBios('');
                      setIdrac('');
                      setEsxiVersion('');
                      setEsxiPatch('');
                    }}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {subCategories.map((sub) => (
                      <option key={sub} value={sub}>{sub}</option>
                    ))}
                  </select>
                </div>
              )}

              {category === 'vCenter' && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Versiyon *</label>
                  <select
                    value={model}
                    onChange={(e) => {
                      setModel(e.target.value);
                      setBios('');
                      setIdrac('');
                      setEsxiVersion('');
                      setEsxiPatch('');
                    }}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {models.map((mod: string) => (
                      <option key={mod} value={mod}>{mod}</option>
                    ))}
                  </select>
                </div>
              )}

              {category && subCategory && category !== 'Veeam' && category !== 'vCenter' && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Model *</label>
                  <select
                    value={model}
                    onChange={(e) => {
                      setModel(e.target.value);
                      setBios('');
                      setIdrac('');
                      setEsxiVersion('');
                      setEsxiPatch('');
                    }}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {models.map((mod: string) => (
                      <option key={mod} value={mod}>{mod}</option>
                    ))}
                  </select>
                </div>
              )}

              {category === 'Veeam' && subCategory && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Versiyon *</label>
                  <select
                    value={subCategory}
                    onChange={(e) => setSubCategory(e.target.value)}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {veeamVersions.map((ver) => (
                      <option key={ver} value={ver}>{ver}</option>
                    ))}
                  </select>
                </div>
              )}

              {category && subCategory && model && biosList.length > 0 && category !== 'Veeam' && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">BIOS Sürümü *</label>
                  <select
                    value={bios}
                    onChange={(e) => setBios(e.target.value)}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {biosList.map((b: string) => (
                      <option key={b} value={b}>{b}</option>
                    ))}
                  </select>
                </div>
              )}

              {category && subCategory && model && idracList.length > 0 && category !== 'Veeam' && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">
                    {category === 'HP' ? 'iLO' : 'iDRAC'} Sürümü *
                  </label>
                  <select
                    value={idrac}
                    onChange={(e) => setIdrac(e.target.value)}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {idracList.map((i) => (
                      <option key={i} value={i}>{i}</option>
                    ))}
                  </select>
                </div>
              )}

              {(category === 'Dell' || category === 'HP') && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">ESXi Sürümü *</label>
                  <select
                    value={esxiVersion}
                    onChange={(e) => {
                      setEsxiVersion(e.target.value);
                      setEsxiPatch('');
                    }}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {esxiVersions.map((ver) => (
                      <option key={ver} value={ver}>{ver}</option>
                    ))}
                  </select>
                </div>
              )}

              {(category === 'Dell' || category === 'HP') && esxiVersion && (
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">ESXi Patch *</label>
                  <select
                    value={esxiPatch}
                    onChange={(e) => setEsxiPatch(e.target.value)}
                    className="w-full px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
                    required
                  >
                    <option value="">Seçin</option>
                    {esxiPatches.map((patch) => (
                      <option key={patch} value={patch}>{patch}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="flex gap-4 pt-8 border-t border-slate-200">
              <button 
                type="submit" 
                className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-4 rounded-lg transition-all shadow-md hover:shadow-lg disabled:bg-slate-300 disabled:shadow-none uppercase tracking-wide"
                disabled={
                  !category || !systemName ||
                  (category === 'vCenter' && !model) ||
                  (category === 'Veeam' && !subCategory) ||
                  (category !== 'Veeam' && category !== 'vCenter' && (!subCategory || !model || !bios || !idrac)) ||
                  ((category === 'Dell' || category === 'HP') && (!esxiVersion || !esxiPatch))
                }
              >
                {editingId ? 'Güncelle' : 'Ekle'}
              </button>
              {editingId && (
                <button 
                  type="button"
                  onClick={handleCancelEdit}
                  className="flex-1 bg-slate-400 hover:bg-slate-500 text-white font-bold py-4 rounded-lg transition-all shadow-md hover:shadow-lg uppercase tracking-wide"
                >
                  İptal
                </button>
              )}
            </div>
          </form>
        </div>

        <div>
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-indigo-600 rounded-lg flex items-center justify-center">
              <span className="text-white text-lg">📊</span>
            </div>
            <h2 className="text-3xl font-bold text-gray-900">Sistemler</h2>
            <span className="ml-auto bg-indigo-600 text-white px-4 py-2 rounded-lg font-bold text-lg">{systems.length}</span>
          </div>
          {systems.length === 0 ? (
            <div className="bg-white rounded-2xl shadow-md p-12 text-center border border-slate-200">
              <p className="text-xl text-gray-500 font-medium">Henüz sistem eklenmemiş</p>
              <p className="text-gray-400 mt-2">Yukarıda formu doldurarak yeni sistem ekleyin</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              {systems.map((system) => (
                <div key={system._id} className="bg-white rounded-2xl shadow-md overflow-hidden hover:shadow-lg transition-all duration-300 border border-slate-200 hover:border-indigo-300">
                  <div className="bg-gradient-to-r from-indigo-600 to-indigo-700 px-8 py-6">
                    <h3 className="text-2xl font-bold text-white mb-1">{system.name}</h3>
                    <div className="flex items-center gap-2">
                      <span className="inline-block w-3 h-3 bg-white rounded-full"></span>
                      <p className="text-indigo-100 text-sm font-medium">{system.category}</p>
                    </div>
                  </div>
                  
                  <div className="px-8 py-6 space-y-5">
                    {system.subCategory && (
                      <div className="pb-4 border-b border-slate-200">
                        <p className="text-xs text-gray-500 font-bold uppercase tracking-wide mb-1">Alt Kategori</p>
                        <p className="text-gray-800 font-semibold">{system.subCategory}</p>
                      </div>
                    )}
                    {system.model && (
                      <div className="pb-4 border-b border-slate-200">
                        <p className="text-xs text-gray-500 font-bold uppercase tracking-wide mb-1">Model</p>
                        <p className="text-gray-800 font-mono text-sm bg-slate-50 px-3 py-2 rounded">{system.model}</p>
                      </div>
                    )}
                    {(system.bios || system.idrac) && (
                      <div className="grid grid-cols-2 gap-4 pb-4 border-b border-slate-200">
                        {system.bios && (
                          <div>
                            <p className="text-xs text-gray-500 font-bold uppercase tracking-wide mb-1">BIOS</p>
                            <p className="text-gray-800 text-sm font-mono bg-slate-50 px-2 py-1 rounded">{system.bios}</p>
                          </div>
                        )}
                        {system.idrac && (
                          <div>
                            <p className="text-xs text-gray-500 font-bold uppercase tracking-wide mb-1">{system.category === 'HP' ? 'ILO' : 'IDRAC'}</p>
                            <p className="text-gray-800 text-sm font-mono bg-slate-50 px-2 py-1 rounded">{system.idrac}</p>
                          </div>
                        )}
                      </div>
                    )}

                    {(system.category === 'Dell' || system.category === 'HP') && system.esxiVersion && (
                      <div className="grid grid-cols-2 gap-4 pt-4 border-t border-slate-200">
                        <div>
                          <p className="text-xs text-gray-500 font-bold uppercase tracking-wide mb-1">ESXi Versiyon</p>
                          <p className="text-gray-800 text-sm font-mono bg-emerald-50 px-3 py-2 rounded border border-emerald-200">{system.esxiVersion}</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500 font-bold uppercase tracking-wide mb-1">ESXi Patch</p>
                          <p className="text-gray-800 text-sm font-mono bg-emerald-50 px-3 py-2 rounded border border-emerald-200 overflow-x-auto">{system.esxiPatch}</p>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="px-8 py-5 bg-slate-50 flex gap-3 border-t border-slate-200">
                    <button
                      onClick={() => handleEdit(system)}
                      className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-lg hover:shadow-md transition-all font-semibold text-sm uppercase tracking-wide"
                    >
                      ✏️ Düzenle
                    </button>
                    <button
                      onClick={() => deleteSystem(system._id)}
                      className="flex-1 bg-red-500 hover:bg-red-600 text-white py-2.5 rounded-lg hover:shadow-md transition-all font-semibold text-sm uppercase tracking-wide"
                    >
                      🗑️ Sil
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}