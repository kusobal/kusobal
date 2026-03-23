'use client';

import { useSession, signOut } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export default function Home() {
  const { data: session, status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === 'loading') return;
    if (!session) {
      router.push('/auth/signin');
    }
  }, [session, status, router]);

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center">
        <div className="text-white text-xl">Yükleniyor...</div>
      </div>
    );
  }

  if (!session) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 text-white py-8 px-6 shadow-xl">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Altyapı Yönetim Sistemi</h1>
            <p className="text-indigo-100 mt-1">Hoş geldiniz, {session.user?.name}</p>
          </div>
          <button
            onClick={() => signOut()}
            className="bg-red-600 hover:bg-red-700 text-white font-semibold px-6 py-2 rounded-lg transition"
          >
            Çıkış
          </button>
        </div>
      </div>

      <div className="max-w-7xl mx-auto p-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-gradient-to-br from-white to-slate-50 rounded-2xl shadow-lg p-8 border border-indigo-200 hover:shadow-xl hover:border-indigo-300 transition-all backdrop-blur-sm">
            <div className="text-4xl font-bold">📊</div>
            <h3 className="text-lg font-bold text-gray-900 mt-4">Müşterilerim</h3>
            <p className="text-slate-600 text-sm mt-2">Tüm müşteri altyapısını yönet</p>
            <a href="/customers" className="mt-4 inline-block bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-4 py-2 rounded-lg transition">
              Git →
            </a>
          </div>

          <div className="bg-white rounded-2xl shadow-lg p-8 border border-slate-200 hover:shadow-xl transition-all">
            <div className="text-4xl font-bold">🖥️</div>
            <h3 className="text-lg font-bold text-gray-900 mt-4">Sistemler</h3>
            <p className="text-slate-600 text-sm mt-2">Sunucu ve cihaz yönetimi</p>
            <a href="/customers" className="mt-4 inline-block bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-4 py-2 rounded-lg transition">
              Git →
            </a>
          </div>

          <div className="bg-white rounded-2xl shadow-lg p-8 border border-slate-200 hover:shadow-xl transition-all">
            <div className="text-4xl font-bold">🔄</div>
            <h3 className="text-lg font-bold text-gray-900 mt-4">Güncellemeler</h3>
            <p className="text-slate-600 text-sm mt-2">BIOS ve Firmware sürümleri</p>
            <a href="/updates" className="mt-4 inline-block bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-4 py-2 rounded-lg transition">
              Git →
            </a>
          </div>
        </div>

        {/* Features */}
        <div className="bg-gradient-to-br from-white to-indigo-50 rounded-2xl shadow-xl p-8 border border-indigo-300 backdrop-blur-sm">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Özellikler</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="flex gap-4">
              <div className="text-3xl">✅</div>
              <div>
                <h3 className="font-semibold text-gray-900">Müşteri Yönetimi</h3>
                <p className="text-slate-600 text-sm">Müşterilerinizi organize edin ve yönetin</p>
              </div>
            </div>
            <div className="flex gap-4">
              <div className="text-3xl">✅</div>
              <div>
                <h3 className="font-semibold text-gray-900">Sistem Takibi</h3>
                <p className="text-slate-600 text-sm">BIOS ve Firmware sürümlerini takip edin</p>
              </div>
            </div>
            <div className="flex gap-4">
              <div className="text-3xl">✅</div>
              <div>
                <h3 className="font-semibold text-gray-900">Düzenle & Sil</h3>
                <p className="text-slate-600 text-sm">Sistem bilgilerini güncelleyin ve silin</p>
              </div>
            </div>
            <div className="flex gap-4">
              <div className="text-3xl">✅</div>
              <div>
                <h3 className="font-semibold text-gray-900">Adlandırma</h3>
                <p className="text-slate-600 text-sm">Sistemlerinize benzersiz isimler verin</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
