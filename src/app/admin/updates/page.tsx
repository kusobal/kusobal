'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';

interface Update {
  _id?: string;
  productType: 'ESXi' | 'vCenter' | 'Veeam' | 'iDRAC' | 'iLO' | 'BIOS';
  vendor: string;
  version: string;
  patch: string;
  releaseDate: string;
  category: 'Security' | 'Bug Fix' | 'Feature' | 'Performance' | 'Stability';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  releaseNotesEN: string;
  releaseNotesTR: string;
  url?: string;
}

export default function AdminUpdatesPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [updates, setUpdates] = useState<Update[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (status === 'unauthenticated') {
      router.push('/auth/signin');
      return;
    }

    if (status === 'authenticated') {
      fetchUpdates();
    }
  }, [status, router]);

  const fetchUpdates = async () => {
    try {
      const response = await fetch('/api/updates?limit=1000');
      if (!response.ok) throw new Error('Failed to fetch updates');
      const data = await response.json();
      setUpdates(data.updates || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  if (status === 'loading' || loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-indigo-200 border-t-indigo-600 mx-auto mb-4"></div>
          <p className="text-slate-600">Loading updates...</p>
        </div>
      </div>
    );
  }

  if (status === 'unauthenticated') {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900">Updates Management</h1>
          <p className="text-slate-600 mt-2">Manage software updates and patches</p>
        </div>

        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
            {error}
          </div>
        )}

        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
            <h2 className="text-lg font-semibold text-slate-900">All Updates ({updates.length})</h2>
            <button
              onClick={fetchUpdates}
              className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition"
            >
              Refresh
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-900">Product</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-900">Patch</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-900">Category</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-900">Severity</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-900">Released</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-900">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {updates.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-slate-600">
                      No updates found
                    </td>
                  </tr>
                ) : (
                  updates.map((update) => (
                    <tr key={update._id} className="hover:bg-slate-50 transition">
                      <td className="px-6 py-4 text-sm text-slate-900 font-medium">{update.productType}</td>
                      <td className="px-6 py-4 text-sm text-slate-700">{update.patch}</td>
                      <td className="px-6 py-4 text-sm text-slate-700">{update.category}</td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={`px-2 py-1 rounded-full text-xs font-semibold ${
                            update.severity === 'Critical'
                              ? 'bg-red-100 text-red-800'
                              : update.severity === 'High'
                              ? 'bg-orange-100 text-orange-800'
                              : update.severity === 'Medium'
                              ? 'bg-yellow-100 text-yellow-800'
                              : 'bg-green-100 text-green-800'
                          }`}
                        >
                          {update.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-700">
                        {new Date(update.releaseDate).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        {update.url && (
                          <a
                            href={update.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-indigo-600 hover:text-indigo-700 font-medium"
                          >
                            View
                          </a>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="mt-8 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <h3 className="font-semibold text-blue-900 mb-2">Database Status</h3>
          <p className="text-blue-800 text-sm">
            Total Updates: <span className="font-bold">{updates.length}</span>
          </p>
        </div>
      </div>
    </div>
  );
}
