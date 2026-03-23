'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [resetUrl, setResetUrl] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (response.ok) {
        setResetUrl(data.resetUrl || '');
        setSent(true);
      } else {
        setError(data.error || 'Hata oluştu');
      }
    } catch (err) {
      setError('Bağlantı hatası');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-gradient-to-br from-white to-slate-50 rounded-3xl shadow-2xl overflow-hidden border-2 border-indigo-300 backdrop-blur-sm">
          {/* Header */}
          <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-700 px-8 py-8">
            <h1 className="text-3xl font-black text-white">Şifre Sıfırla</h1>
            <p className="text-indigo-100 mt-2">Şifreni yenile</p>
          </div>

          {/* Form */}
          <div className="px-8 py-8">
            {!sent ? (
              <form onSubmit={handleSubmit} className="space-y-6">
                <p className="text-gray-600 text-sm">
                  Hesabınızla ilişkili e-posta adresini gir. Şifre sıfırlama linki göndereceğiz.
                </p>

                {error && (
                  <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg font-medium text-sm">
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

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-lg transition-all disabled:bg-gray-400 shadow-md hover:shadow-lg"
                >
                  {loading ? 'Gönderiliyor...' : 'Şifre Sıfırlama Linki Gönder'}
                </button>
              </form>
            ) : (
              <div className="text-center space-y-4">
                <div className="text-5xl mb-4">✓</div>
                <h2 className="text-xl font-bold text-gray-900">Başarılı!</h2>
                <p className="text-gray-600">
                  Şifre sıfırlama linki <span className="font-semibold">{email}</span> adresine gönderildi.
                </p>
                <p className="text-sm text-gray-500">
                  E-postanı kontrol et ve linkine tıkla. Link 10 dakika geçerli.
                </p>

                {resetUrl && (
                  <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg mt-6">
                    <p className="text-xs text-gray-600 mb-2">TEST MOD - Development Reset Linki:</p>
                    <a
                      href={resetUrl}
                      className="text-blue-600 hover:text-blue-700 font-mono text-xs break-all underline block"
                    >
                      {resetUrl}
                    </a>
                  </div>
                )}

                <button
                  onClick={() => {
                    setEmail('');
                    setSent(false);
                    setResetUrl('');
                  }}
                  className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-lg transition-all"
                >
                  Başka E-posta Dene
                </button>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="bg-slate-50 px-8 py-6 border-t border-slate-200 text-center">
            <p className="text-gray-600 text-sm">
              Geri dön{' '}
              <Link href="/auth/signin" className="text-indigo-600 font-bold hover:text-indigo-700">
                giriş sayfasına
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
