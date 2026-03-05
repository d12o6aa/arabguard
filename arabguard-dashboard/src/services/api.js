/**
 * src/services/api.js
 * ===================
 * ArabGuard — All HTTP calls to the FastAPI backend.
 *
 * Base URL: VITE_API_URL env var (default http://localhost:8000)
 *
 * All responses arrive in camelCase — the backend's ConfigDict(alias_generator=to_camel)
 * handles the conversion automatically. Read fields directly:
 *   data.totalRequests   data.isBlocked   data.aiConfidence  etc.
 *
 * No mock data is imported here. Every function hits a real endpoint.
 */

const BASE_URL =
  import.meta.env.VITE_API_URL?.replace(/\/$/, '') || 'http://localhost:8000';

// ── Core request helper ────────────────────────────────────────────────────────
async function _request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const err = await res.json();
      detail = err.detail || JSON.stringify(err);
    } catch (_) { /* ignore */ }
    throw new Error(`[${res.status}] ${detail}`);
  }
  return res.json();
}

// ── Health ────────────────────────────────────────────────────────────────────
/**
 * GET /health
 * Returns: { backend, model, modelId, device, aiEnabled, version }
 */
export async function checkHealth() {
  return _request('/health');
}

// ── Analysis ──────────────────────────────────────────────────────────────────
/**
 * POST /analyze
 * camelCase response fields:
 *   decision, score, isBlocked, isFlagged, status, risk, vector,
 *   normalizedText, matchedPattern, allMatchedPatterns,
 *   aiConfidence, aiPrediction, decisionSource,
 *   langDist, reason, pipelineSteps, timestamp, id
 */
export async function analyzeText(text, { useAi = true, debug = false, policies = {} } = {}) {
  return _request('/analyze', {
    method: 'POST',
    body: JSON.stringify({ text, use_ai: useAi, debug, policies }),
  });
}

/** POST /analyze/batch → GuardResult[] */
export async function analyzeTextBatch(texts, { useAi = true, policies = {} } = {}) {
  return _request('/analyze/batch', {
    method: 'POST',
    body: JSON.stringify({ texts, use_ai: useAi, policies }),
  });
}

// ── Analytics ─────────────────────────────────────────────────────────────────
/**
 * GET /analytics/summary?window_hours=24
 * camelCase fields:
 *   totalRequests, totalBlocked, totalFlagged, totalSafe,
 *   threatRate, aiAccuracy, topVector,
 *   languageDist    → [{ subject, value }]              ← Recharts RadarChart
 *   attackBreakdown → [{ name, count, color }]           ← Recharts BarChart
 *   timeline        → [{ time, blocked, flagged, safe }] ← AreaChart
 */
export async function fetchDashboardStats(windowHours = 24) {
  return _request(`/analytics/summary?window_hours=${windowHours}`);
}

/** GET /analytics/language-distribution → [{ subject, value }] */
export async function fetchLanguageDistribution() {
  return _request('/analytics/language-distribution');
}

// ── Threat Logs ───────────────────────────────────────────────────────────────
/**
 * GET /logs/threats?page=1&page_size=50&filter=ALL
 * Returns: { items: ThreatLogItem[], total, page, pages }
 */
export async function fetchThreatLogs({ page = 1, pageSize = 50, filter = 'ALL' } = {}) {
  return _request(`/logs/threats?page=${page}&page_size=${pageSize}&filter=${filter}`);
}

// ── Review Queue ──────────────────────────────────────────────────────────────
/**
 * GET /queue?filter=ALL&page=1&page_size=50
 * Returns ALL records, filterable by status.
 * Response: { items: QueueItem[], total, filterApplied }
 * Item camelCase fields: id, text, normalized, score, risk, status,
 *   vector, aiConfidence, aiPrediction, timestamp
 */
export async function fetchQueue({ filter = 'ALL', page = 1, pageSize = 50 } = {}) {
  return _request(`/queue?filter=${filter}&page=${page}&page_size=${pageSize}`);
}

// Alias for backward-compat (used in legacy hooks)
export const fetchAmbiguousQueue = fetchQueue;

/**
 * POST /queue/{id}/review
 * action: 'approve' | 'train' | 'block'
 * 'train' immediately saves to retraining_set.jsonl on the backend.
 */
export async function submitReviewDecision(
  itemId,
  action,
  notes = '',
  reviewerId = 'security_officer',
) {
  return _request(`/queue/${itemId}/review`, {
    method: 'POST',
    body: JSON.stringify({ action, notes, reviewer_id: reviewerId }),
  });
}

// ── Settings / Policies ────────────────────────────────────────────────────────
/** GET /settings/policies → current policy state */
export async function fetchPolicies() {
  return _request('/settings/policies');
}

/** PATCH /settings/policies/{key} → toggle a single policy */
export async function updatePolicy(policyKey, enabled) {
  return _request(`/settings/policies/${policyKey}`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
}

/** PUT /settings/policies → replace all policies */
export async function updateAllPolicies(policies) {
  return _request('/settings/policies', {
    method: 'PUT',
    body: JSON.stringify(policies),
  });
}

// ── Default export (for code that uses `import api from './api'`) ──────────────
export default {
  checkHealth,
  analyzeText,
  analyzeTextBatch,
  fetchDashboardStats,
  fetchLanguageDistribution,
  fetchThreatLogs,
  fetchQueue,
  fetchAmbiguousQueue,
  submitReviewDecision,
  fetchPolicies,
  updatePolicy,
  updateAllPolicies,
};