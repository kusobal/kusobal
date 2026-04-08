'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';

interface Update {
  _id?: string;
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

const sampleUpdates: Update[] = [
  {
    productType: 'ESXi',
    vendor: 'Broadcom',
    version: '8.0.3',
    patch: '8.0.3P',
    releaseDate: new Date().toISOString().split('T')[0],
    category: 'Security',
    severity: 'High',
    releaseNotesEN: `ESXi 8.0.3P includes critical security patches:

- CVE-2024-XXXX: Fixed privilege escalation vulnerability
- CVE-2024-XXXX: Fixed memory corruption issue
- Performance improvements in VM scheduling
- Improved networking stack stability

Recommended for all customer deployments.`,
    releaseNotesTR: `ESXi 8.0.3P kritik guvenlik yamalarini icerir:

- CVE-2024-XXXX: Ayrikalik yukselmesi guvenlik acigi giderildi
- CVE-2024-XXXX: Bellek bozulmasi sorunu duzeltildi
- VM zamanlama performans iyilestirmeleri
- Ag yigini stabilite iyilestirmeleri

Tum musteri dagitim lari icin onerilir.`,
    url: 'https://support.broadcom.com/web/ecx/support-content-notification',
  },
  {
    productType: 'vCenter',
    vendor: 'VMware',
    version: '8.0',
    patch: '8.0.1',
    releaseDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    category: 'Bug Fix',
    severity: 'Medium',
    releaseNotesEN: `vCenter Server 8.0.1 Update:

- Fixed vSphere Client connectivity issues
- Improved database performance for large environments
- Fixed backup/restore functionality
- Updated SSL certificates

Please update within 30 days.`,
    releaseNotesTR: `vCenter Server 8.0.1 Guncellemesi:

- vSphere Client baglantı sorunları duzeltildi
- Buyuk ortamlar icin veritabanı performansı iyilestirildi
- Yedekleme/geri yukleme işlevi duzeltildi
- SSL sertifikalaları guncellendi

Lutfen 30 gun icinde guncelleyin.`,
    url: 'https://docs.vmware.com/en/vCenter-Server/8.0/rn/vcenter-server-801-release-notes.html',
  },
  {
    productType: 'iDRAC',
    vendor: 'Dell',
    version: '10',
    patch: '10.1.0.1',
    releaseDate: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    category: 'Security',
    severity: 'Critical',
    releaseNotesEN: `iDRAC10 Firmware 10.1.0.1:

- CRITICAL: Fixed IPMI vulnerability
- Fixed Redfish API authentication bypass
- Improved thermal management
- Enhanced logging capabilities

RECOMMENDED: Apply immediately`,
    releaseNotesTR: `iDRAC10 Firmware 10.1.0.1:

- KRİTİK: IPMI guvenlik acigi duzeltildi
- Redfish API kimlik dogrulama bypass'ı duzeltildi
- Termal yonetimi iyilestirildi
- Gunlekleme yetenekleri iyilestirildi

ONERILEN: Hemen uygulayin`,
    url: 'https://www.dell.com/support/home/en-us/product-support/product/idrac10/docs',
  },
];

export default function AdminPanel() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [isAdmin, setIsAdmin] = useState(false);
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (status === 'authenticated') {
      const user = session?.user as any;
      // Şimdilik test için herkes admin olabilir - sonra email kontrolü ekle
      setIsAdmin(true);
    }
  }, [session, status]);

  const handleAddSampleData = async () => {
    setLoading(true);
    try {
      for (const sample of sampleUpdates) {
        await fetch('/api/updates', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(sample),
        });
      }
      setMessage('OK Ornek veriler basarili eklendi');
    } catch (error) {
      setMessage('HATA: Ornek veriler eklenemedi');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  if (status === 'loading') {
    return <div className="flex items-center justify-center min-h-screen">Yukleniyor...</div>;
  }

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <p className="text-2xl font-bold text-red-600">Yetkili degilsiniz</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50">
      <div className="bg-white border-b border-slate-200 sticky top-0 z-40 shadow-sm">
        <div className="max-w-7xl mx-auto px-8 py-6">
          <button type="button" onClick={() => router.push('/updates')} className="text-sm font-semibold text-indigo-600 hover:text-indigo-700 mb-4 flex items-center gap-2 transition-colors">
            <span>📦</span> Guncellemeleri Gor
          </button>
          <h1 className="text-4xl font-black text-gray-900">Admin Panel</h1>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-8 py-12">
        {message && (
          <div className="mb-8 p-4 bg-white border border-slate-200 rounded-lg text-center font-bold">
            {message}
          </div>
        )}

        <div className="bg-white rounded-2xl shadow-lg p-8 border border-slate-200">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Ornek Veri Yukle</h2>
          <button
            onClick={handleAddSampleData}
            disabled={loading}
            className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white font-bold rounded-lg disabled:bg-gray-400"
          >
            Ornek Verileri Yukle
          </button>
          <p className="text-sm text-gray-600 mt-3">
            ESXi, vCenter, iDRAC, Veeam ornek guncellemelerini database ekler
          </p>
        </div>
      </div>
    </div>
  );
}
