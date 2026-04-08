'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';

interface Customer {
  _id: string;
  name: string;
  createdAt?: string;
}

export default function Customers() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (status === 'loading') return;
    if (!session) {
      router.push('/auth/signin');
    } else {
      fetchCustomers();
    }
  }, [session, status, router]);

  const fetchCustomers = async () => {
    const res = await fetch('/api/customers');
    if (res.ok) {
      const data = await res.json();
      setCustomers(data);
    }
    setLoading(false);
  };

  const addCustomer = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetch('/api/customers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (res.ok) {
      setName('');
      fetchCustomers();
    }
  };

  if (status === 'loading' || loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 flex items-center justify-center">
        <div className="text-gray-700 text-xl">Yükleniyor...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 sticky top-0 z-40 shadow-xl text-white">
        <div className="max-w-7xl mx-auto px-8 py-6">
          <button type="button" onClick={() => router.push('/')} className="text-sm font-semibold text-indigo-100 hover:text-white flex items-center gap-2 transition-colors mb-4">
            ← Anasayfa
          </button>
          <h1 className="text-4xl font-black text-white">👥 Müşteriler</h1>
          <p className="text-indigo-100 text-lg mt-2">Altyapı ve sistem yönetimi sistemi</p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-8 py-12">
        {/* Add Customer Form */}
        <div className="bg-gradient-to-br from-white to-slate-50 rounded-2xl shadow-lg p-12 mb-12 border border-indigo-300 backdrop-blur-sm">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Yeni Müşteri Ekle</h2>
          <form onSubmit={addCustomer} className="flex gap-4">
            <input
              type="text"
              placeholder="Müşteri adı giriniz..."
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1 px-5 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all bg-white text-gray-900"
              required
            />
            <button 
              type="submit" 
              className="bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-bold px-8 py-3 rounded-lg transition-all shadow-md hover:shadow-lg"
            >
              Ekle
            </button>
          </form>
        </div>

        {/* Customers Grid */}
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Müşteri Listesi ({customers.length})</h2>
          {customers.length === 0 ? (
            <div className="bg-gradient-to-br from-white to-slate-50 rounded-2xl shadow-md p-12 text-center border border-indigo-300 backdrop-blur-sm">
              <p className="text-lg text-gray-500">Henüz müşteri eklenmemiş</p>
              <p className="text-sm text-gray-400 mt-2">Yukarıdaki form ile yeni müşteri ekleyerek başlayın</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {customers.map((customer) => (
                <div 
                  key={customer._id} 
                  className="bg-gradient-to-br from-white to-indigo-50 rounded-2xl shadow-md hover:shadow-xl transition-all transform hover:scale-105 cursor-pointer overflow-hidden border border-indigo-300 hover:border-purple-400 backdrop-blur-sm"
                  onClick={() => router.push(`/customers/${customer._id}`)}
                >
                  <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 px-8 py-6">
                    <h3 className="text-xl font-bold text-white">{customer.name}</h3>
                  </div>
                  <div className="px-8 py-6">
                    <button className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-bold py-3 rounded-lg transition-all">
                      Sistemler → 
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