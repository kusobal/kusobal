'use client';

import { useState } from 'react';
import { useRouter, useParams } from 'next/navigation';

export default function ResetPasswordPage() {
  const router = useRouter();
  const params = useParams();
  const token = params.token as string;

  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (newPassword !== confirmPassword) {
      setError('Şifreler eşleşmiyor');
      return;
    }

    if (newPassword.length < 6) {
      setError('Şifre en az 6 karakter olmalı');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, newPassword }),
      });

      if (response.ok) {
        setMessage('Şifre başarıyla sıfırlandı!');
        setTimeout(() => {
          router.push('/auth/signin');
        }, 2000);
      } else {
        const data = await response.json();
        setError(data.error || 'Şifre sıfırlanamadı');
      }
    } catch (err) {
      setError('Hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 flex items-center justify-center px-4">
      <div className="bg-gradient-to-br from-white to-slate-50 rounded-3xl shadow-2xl p-8 w-full max-w-md border-2 border-indigo-300 backdrop-blur-sm">
        <h1 className="text-3xl font-black text-gray-900 mb-2">Şifre Sıfırla</h1>
        <p className="text-slate-500 mb-6">Yeni şifreni belirle</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-bold text-gray-700 mb-2">Yeni Şifre</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              placeholder="Şifre..."
              required
            />
          </div>

          <div>
            <label className="block text-sm font-bold text-gray-700 mb-2">Şifreyi Onayla</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              placeholder="Şifreyi tekrar gir..."
              required
            />
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm font-medium">
              {error}
            </div>
          )}

          {message && (
            <div className="p-3 bg-green-50 border border-green-200 text-green-700 rounded-lg text-sm font-medium">
              {message}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-lg transition-all disabled:bg-gray-400"
          >
            {loading ? 'Şifre Sıfırlanıyor...' : 'Şifreyi Sıfırla'}
          </button>
        </form>

        <p className="text-center text-sm text-slate-600 mt-6">
          Giriş yap{' '}
          <button
            type="button"
            onClick={() => router.push('/auth/signin')}
            className="text-indigo-600 hover:text-indigo-700 font-bold"
          >
            buradan
          </button>
        </p>
      </div>
    </div>
  );
}
