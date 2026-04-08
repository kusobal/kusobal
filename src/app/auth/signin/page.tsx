'use client';

import { useState } from 'react';
import { signIn } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function SignIn() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    const result = await signIn('credentials', {
      email,
      password,
      redirect: false,
    });
    
    if (result?.ok) {
      router.push('/customers');
    } else {
      setError('E-posta veya şifre yanlış');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-gradient-to-br from-white to-slate-50 rounded-3xl shadow-2xl overflow-hidden border-2 border-indigo-300 backdrop-blur-sm">
          {/* Header */}
          <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 px-8 py-8\">
            <h1 className="text-3xl font-black text-white">Giriş Yap</h1>
            <p className="text-indigo-100 mt-2">Altyapı Yönetim Sistemi</p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="px-8 py-8 space-y-6">
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg font-medium">
                {error}
              </div>
            )}

            <div>
              <label className="block text-sm font-bold text-gray-700 mb-3">E-posta</label>
              <input
                type="email"
                placeholder="ornek@domain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-bold text-gray-700 mb-3">Şifre</label>
              <input
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                required
              />
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2">
                <input type="checkbox" className="rounded" />
                <span className="text-sm text-gray-600">Beni hatırla</span>
              </label>
              <Link href="/auth/forgot-password" className="text-sm text-indigo-600 hover:text-indigo-700 font-semibold">
                Şifremi Unuttum
              </Link>
            </div>

            <button 
              type="submit"
              disabled={loading}
              className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-lg transition-all disabled:bg-gray-400 shadow-md hover:shadow-lg"
            >
              {loading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
            </button>
          </form>

          {/* Footer */}
          <div className="bg-slate-50 px-8 py-6 border-t border-slate-200">
            <p className="text-center text-gray-600">
              Hesabınız yok mu?{' '}
              <Link href="/auth/register" className="text-indigo-600 font-bold hover:text-indigo-700">
                Kayıt Ol
              </Link>
            </p>
          </div>
        </div>

        {/* Demo Info */}
        <div className="mt-8 bg-white rounded-2xl shadow-md p-6 border border-slate-200">
          <h3 className="font-bold text-gray-900 mb-3">Demo Hesap</h3>
          <p className="text-sm text-gray-600">E-posta: <span className="font-mono font-semibold">test@example.com</span></p>
          <p className="text-sm text-gray-600">Şifre: <span className="font-mono font-semibold">Kursat</span></p>
        </div>
      </div>
    </div>
  );
}