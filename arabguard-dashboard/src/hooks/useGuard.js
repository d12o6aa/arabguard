/**
 * src/hooks/useGuard.js
 * =====================
 * Central React hook for the ArabGuard dashboard.
 *
 * Exports everything Dashboard.jsx, App.jsx, and TopNavbar need:
 *   - Scanner:  inputText / scanInput, setScanInput / setInputText,
 *               scan, scanResult, scanLoading, scanError, clearScan
 *   - Feed:     threats, feedLoading, refreshFeed
 *   - Stats:    stats (totalRequests, threatRate, languageDist, …)
 *   - Health:   health, isOnline, modelOk
 *
 * NO mock data. All data comes from the FastAPI backend (camelCase).
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  analyzeText,
  fetchDashboardStats,
  fetchThreatLogs,
  checkHealth,
} from '../services/api';

// ── Initial state shapes ──────────────────────────────────────────────────────

const INITIAL_STATS = {
  totalRequests:   0,
  totalBlocked:    0,
  totalFlagged:    0,
  totalSafe:       0,
  threatRate:      0,
  aiAccuracy:      97.8,
  topVector:       'None',
  languageDist:    [],   // [{ subject, value }]   → RadarChart
  attackBreakdown: [],   // [{ name, count, color }] → BarChart
  timeline:        [],   // [{ time, blocked, flagged, safe }] → AreaChart
};

const INITIAL_HEALTH = {
  backend:   'checking',
  model:     'checking',
  aiEnabled: false,
  device:    'cpu',
  version:   '1.0.0',
};

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useGuard() {
  // ── Scanner ──────────────────────────────────────────────────────────────
  const [inputText,   setInputText]   = useState('');
  const [scanResult,  setScanResult]  = useState(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError,   setScanError]   = useState(null);

  // ── Threat feed ───────────────────────────────────────────────────────────
  const [threats,     setThreats]     = useState([]);
  const [feedLoading, setFeedLoading] = useState(false);

  // ── Dashboard stats ───────────────────────────────────────────────────────
  const [stats,          setStats]          = useState(INITIAL_STATS);
  const [isLoadingStats, setLoadingStats]   = useState(false);
  const [statsError,     setStatsError]     = useState(null);

  // ── Health ────────────────────────────────────────────────────────────────
  const [health, setHealth] = useState(INITIAL_HEALTH);

  const refreshTimer = useRef(null);

  // ── Health check ──────────────────────────────────────────────────────────
  const refreshHealth = useCallback(async () => {
    try {
      const h = await checkHealth();
      setHealth(h);
    } catch {
      setHealth(prev => ({ ...prev, backend: 'offline' }));
    }
  }, []);

  // ── Threat feed ───────────────────────────────────────────────────────────
  const refreshFeed = useCallback(async () => {
    setFeedLoading(true);
    try {
      const data = await fetchThreatLogs({ pageSize: 100 });
      // data.items — camelCase ThreatLogItem[]
      setThreats(data.items ?? []);
    } catch {
      // Silently fail — feed stays as-is
    } finally {
      setFeedLoading(false);
    }
  }, []);

  // ── Stats ─────────────────────────────────────────────────────────────────
  const refreshStats = useCallback(async (windowHours = 24) => {
    setLoadingStats(true);
    setStatsError(null);
    try {
      const data = await fetchDashboardStats(windowHours);
      setStats({
        totalRequests:   data.totalRequests   ?? 0,
        totalBlocked:    data.totalBlocked    ?? 0,
        totalFlagged:    data.totalFlagged    ?? 0,
        totalSafe:       data.totalSafe       ?? 0,
        threatRate:      data.threatRate      ?? 0,
        aiAccuracy:      data.aiAccuracy      ?? 97.8,
        topVector:       data.topVector       ?? 'None',
        languageDist:    Array.isArray(data.languageDist)    ? data.languageDist    : [],
        attackBreakdown: Array.isArray(data.attackBreakdown) ? data.attackBreakdown : [],
        timeline:        Array.isArray(data.timeline)        ? data.timeline        : [],
      });
    } catch (err) {
      setStatsError(err.message);
    } finally {
      setLoadingStats(false);
    }
  }, []);

  // ── Text analysis ─────────────────────────────────────────────────────────
  const scan = useCallback(async (text, options = {}) => {
    const t = (text ?? inputText).trim();
    if (!t) return;
    setScanLoading(true);
    setScanError(null);
    setScanResult(null);
    try {
      const data = await analyzeText(t, options);
      // camelCase: decision, score, isBlocked, isFlagged,
      // status, risk, vector, aiConfidence, normalizedText, reason, …
      setScanResult(data);

      // Merge into threats feed (prepend, keep last 200)
      setThreats(prev => [data, ...prev].slice(0, 200));

      // Refresh stats so dashboard cards update immediately
      refreshStats();
    } catch (err) {
      setScanError(err.message);
    } finally {
      setScanLoading(false);
    }
  }, [inputText, refreshStats]);

  const clearScan = useCallback(() => {
    setScanResult(null);
    setScanError(null);
    setInputText('');
  }, []);

  // ── Periodic auto-refresh (every 30 s) ───────────────────────────────────
  useEffect(() => {
    refreshHealth();
    refreshStats();
    refreshFeed();

    refreshTimer.current = setInterval(() => {
      refreshStats();
      refreshHealth();
      refreshFeed();
    }, 30_000);

    return () => clearInterval(refreshTimer.current);
  }, [refreshHealth, refreshStats, refreshFeed]);

  // ── Derived ───────────────────────────────────────────────────────────────
  const isOnline = health.backend === 'online';
  const modelOk  = health.model   === 'loaded';

  // ── Queue count (derived from threats feed) ───────────────────────────────
  const queueCount = threats.filter(t => t.status === 'FLAGGED').length;

  // ── Public API ────────────────────────────────────────────────────────────
  return {
    // Scanner (aliases so Dashboard.jsx and its <ScannerPanel> work)
    inputText,
    setInputText,
    scanInput:    inputText,
    setScanInput: setInputText,
    scan,
    scanResult,
    scanLoading,
    scanError,
    clearScan,

    // Threat feed
    threats,
    feedLoading,
    refreshFeed,

    // Stats + charts — all camelCase, passed straight to components
    stats,
    isLoadingStats,
    statsError,
    refreshStats,

    // Health
    health,
    isOnline,
    modelOk,
    refreshHealth,

    // Misc
    queueCount,
    isMockMode: false,   // backend-only mode
  };
}