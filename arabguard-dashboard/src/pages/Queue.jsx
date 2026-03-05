/**
 * src/pages/Queue.jsx
 * ===================
 * Human-in-the-Loop Review Queue.
 *
 * What changed
 * ------------
 * - NO mock data.  All data from GET /queue.
 * - Shows ALL records (not just FLAG) with status filter tabs.
 * - "Train" button calls POST /queue/{id}/review with action="train"
 *   → backend immediately saves the entry to retraining_set.jsonl.
 * - Filter tabs: All | Blocked | Flagged | Safe
 * - camelCase fields used directly: aiConfidence, aiPrediction, etc.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { fetchQueue, submitReviewDecision } from '../services/api';

// ── Risk/Status color helpers ─────────────────────────────────────────────────

const STATUS_COLORS = {
  BLOCKED: 'bg-red-500/20 text-red-300 border-red-500/30',
  FLAGGED: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  SAFE:    'bg-green-500/20 text-green-300 border-green-500/30',
};

const RISK_COLORS = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-green-400',
};

function StatusBadge({ status }) {
  return (
    <span className={`px-2 py-0.5 rounded-full border text-xs font-semibold ${STATUS_COLORS[status] || STATUS_COLORS.SAFE}`}>
      {status}
    </span>
  );
}

function ScoreMeter({ score }) {
  const pct = Math.min(score, 300) / 300 * 100;
  const color = score >= 120 ? '#f43f5e' : score >= 80 ? '#facc15' : '#34d399';
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 rounded-full bg-zinc-700">
        <div className="h-1.5 rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-mono text-zinc-300">{score}</span>
    </div>
  );
}

// ── Filter Tabs ───────────────────────────────────────────────────────────────

const FILTERS = ['ALL', 'BLOCKED', 'FLAGGED', 'SAFE'];

function FilterTabs({ active, onChange }) {
  return (
    <div className="flex gap-1 p-1 bg-zinc-800 rounded-lg w-fit">
      {FILTERS.map(f => (
        <button
          key={f}
          onClick={() => onChange(f)}
          className={`px-3 py-1 rounded text-xs font-semibold transition-all ${
            active === f
              ? 'bg-blue-600 text-white shadow'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-700'
          }`}
        >
          {f}
        </button>
      ))}
    </div>
  );
}

// ── Action Buttons ────────────────────────────────────────────────────────────

function ActionButtons({ item, onAction, loadingId }) {
  const busy = loadingId === item.id;
  return (
    <div className="flex gap-2">
      <button
        onClick={() => onAction(item.id, 'approve')}
        disabled={busy}
        title="Mark as safe"
        className="px-2.5 py-1 rounded text-xs font-semibold bg-green-600/20 text-green-300 border border-green-600/30 hover:bg-green-600/40 disabled:opacity-40 transition-all"
      >
        ✓ Approve
      </button>
      <button
        onClick={() => onAction(item.id, 'train')}
        disabled={busy}
        title="Save to retraining dataset"
        className="px-2.5 py-1 rounded text-xs font-semibold bg-blue-600/20 text-blue-300 border border-blue-600/30 hover:bg-blue-600/40 disabled:opacity-40 transition-all"
      >
        🧠 Train
      </button>
      <button
        onClick={() => onAction(item.id, 'block')}
        disabled={busy}
        title="Confirm as malicious"
        className="px-2.5 py-1 rounded text-xs font-semibold bg-red-600/20 text-red-300 border border-red-600/30 hover:bg-red-600/40 disabled:opacity-40 transition-all"
      >
        ✕ Block
      </button>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function Queue() {
  const [items,      setItems]      = useState([]);
  const [total,      setTotal]      = useState(0);
  const [filter,     setFilter]     = useState('ALL');
  const [page,       setPage]       = useState(1);
  const [pageSize]                  = useState(50);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState(null);
  const [loadingId,  setLoadingId]  = useState(null);
  const [toast,      setToast]      = useState(null);

  // ── Load queue ─────────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchQueue({ filter, page, pageSize });
      // data.items → camelCase QueueItem[]
      // data.total, data.filterApplied
      setItems(data.items ?? []);
      setTotal(data.total ?? 0);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [filter, page, pageSize]);

  useEffect(() => {
    setPage(1); // reset to page 1 when filter changes
  }, [filter]);

  useEffect(() => {
    load();
  }, [load]);

  // ── Review action ──────────────────────────────────────────────────────────

  const handleAction = useCallback(async (itemId, action) => {
    setLoadingId(itemId);
    try {
      const res = await submitReviewDecision(itemId, action);
      const msg = res.message || `${action} recorded.`;

      // Show toast
      setToast({ action, msg });
      setTimeout(() => setToast(null), 3500);

      // Remove item from list after decision
      setItems(prev => prev.filter(i => i.id !== itemId));
      setTotal(prev => Math.max(0, prev - 1));
    } catch (err) {
      setToast({ action: 'error', msg: err.message });
      setTimeout(() => setToast(null), 4000);
    } finally {
      setLoadingId(null);
    }
  }, []);

  // ── Pagination ─────────────────────────────────────────────────────────────

  const totalPages = Math.ceil(total / pageSize);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Review Queue</h1>
          <p className="text-zinc-400 text-sm mt-1">
            {total} record{total !== 1 ? 's' : ''}
            {filter !== 'ALL' ? ` (filter: ${filter})` : ''} •
            <span className="text-blue-400"> 🧠 Train saves to retraining_set.jsonl</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <FilterTabs active={filter} onChange={setFilter} />
          <button
            onClick={load}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 text-xs font-semibold transition-all disabled:opacity-40"
          >
            {loading ? '…' : '↻ Refresh'}
          </button>
        </div>
      </div>

      {/* Toast notification */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg shadow-xl border text-sm font-medium transition-all ${
          toast.action === 'error'
            ? 'bg-red-900/80 border-red-500/50 text-red-200'
            : toast.action === 'train'
            ? 'bg-blue-900/80 border-blue-500/50 text-blue-200'
            : toast.action === 'approve'
            ? 'bg-green-900/80 border-green-500/50 text-green-200'
            : 'bg-orange-900/80 border-orange-500/50 text-orange-200'
        }`}>
          {toast.action === 'train' && '🧠 '}
          {toast.action === 'approve' && '✓ '}
          {toast.action === 'block' && '✕ '}
          {toast.msg}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-900/30 border border-red-500/40 rounded-lg p-4 text-red-300 text-sm">
          ⚠ {error}
        </div>
      )}

      {/* Table */}
      {loading && items.length === 0 ? (
        <div className="text-center py-20 text-zinc-500">Loading…</div>
      ) : items.length === 0 ? (
        <div className="text-center py-20 text-zinc-500">
          No records {filter !== 'ALL' ? `with status "${filter}"` : ''}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-zinc-700/60 bg-zinc-900/60">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-700/60 text-zinc-400 text-xs uppercase tracking-wide">
                <th className="text-left px-4 py-3 w-1/3">Text</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Score</th>
                <th className="text-left px-4 py-3">Risk</th>
                <th className="text-left px-4 py-3">Vector</th>
                <th className="text-left px-4 py-3">AI Conf.</th>
                <th className="text-left px-4 py-3">Time</th>
                <th className="text-left px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {items.map(item => (
                <tr key={item.id} className="hover:bg-zinc-800/40 transition-colors group">
                  {/* Text cell — truncated, full on hover */}
                  <td className="px-4 py-3">
                    <div className="max-w-xs">
                      <p
                        className="text-zinc-200 truncate font-mono text-xs"
                        title={item.text}
                      >
                        {item.text || '—'}
                      </p>
                      {item.normalized && item.normalized !== item.text && (
                        <p
                          className="text-zinc-500 truncate font-mono text-xs mt-0.5"
                          title={item.normalized}
                        >
                          ↳ {item.normalized}
                        </p>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={item.status} /></td>
                  <td className="px-4 py-3"><ScoreMeter score={item.score} /></td>
                  <td className={`px-4 py-3 text-xs font-bold ${RISK_COLORS[item.risk] || 'text-zinc-400'}`}>
                    {item.risk}
                  </td>
                  <td className="px-4 py-3 text-zinc-400 text-xs max-w-[140px] truncate" title={item.vector}>
                    {item.vector || '—'}
                  </td>
                  <td className="px-4 py-3 text-zinc-400 font-mono text-xs">
                    {/* aiConfidence — camelCase from backend */}
                    {item.aiConfidence != null
                      ? `${(item.aiConfidence * 100).toFixed(0)}%`
                      : <span className="text-zinc-600">N/A</span>
                    }
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs whitespace-nowrap">
                    {new Date(item.timestamp).toLocaleString('en-GB', {
                      hour: '2-digit', minute: '2-digit',
                      day: '2-digit', month: 'short',
                    })}
                  </td>
                  <td className="px-4 py-3">
                    <ActionButtons
                      item={item}
                      onAction={handleAction}
                      loadingId={loadingId}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-zinc-500 pt-2">
          <span>Page {page} of {totalPages} ({total} total)</span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 transition-all"
            >
              ← Prev
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 transition-all"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}