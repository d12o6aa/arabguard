/**
 * src/hooks/usePolicies.js
 * ========================
 * Loads guardrail policies from GET /settings/policies.
 * Falls back to local defaults if the backend is unreachable.
 * NO import from mockData.js.
 */

import { useState, useEffect, useCallback } from 'react';
import { fetchPolicies, updatePolicy } from '../services/api';

// ── Local defaults (used only when the API is unreachable) ─────────────────────
const DEFAULT_POLICIES = {
  franco:       { enabled: true,  label: 'Block Franco-Arabic Injection',   description: 'Detect & block Franko transliterated attacks (e.g. t2oly, 3adeit)',       color: 'red'     },
  nationalId:   { enabled: true,  label: 'Mask Egyptian National IDs',      description: 'Auto-redact 14-digit IDs starting with 2 or 3',                            color: 'blue'    },
  slang:        { enabled: true,  label: 'Sentiment-Based Slang Filter',    description: 'Flag hostile colloquial dialect slang patterns',                            color: 'purple'  },
  aiLayer:      { enabled: true,  label: 'AI Deep Analysis (MARBERT)',      description: 'Run MARBERT model for borderline cases (score 60–119)',                     color: 'emerald' },
  splitLetter:  { enabled: true,  label: 'Split-Letter Deobfuscation',      description: 'Merge i-g-n-o-r-e style payloads before scoring',                          color: 'blue'    },
  base64Hex:    { enabled: true,  label: 'Base64 / Hex Decode',             description: 'Detect and decode encoded injection payloads',                              color: 'violet'  },
  unicodeNorm:  { enabled: true,  label: 'Unicode Confusable Normalization', description: 'Replace visually similar characters (e.g. а→a, о→o)',                     color: 'emerald' },
  rot13:        { enabled: false, label: 'ROT-13 Deobfuscation',            description: 'Reverse ROT-13 encoding to detect hidden keywords',                        color: 'purple'  },
};

// ── Convert flat backend dict → UI policy shape ────────────────────────────────
// Backend returns: { franco: true, national_id: true, ai_layer: true, … }
// We map snake_case keys to camelCase and merge with label/description/color.
function mergePoliciesFromAPI(apiData) {
  const keyMap = {
    franco:       'franco',
    national_id:  'nationalId',
    slang:        'slang',
    ai_layer:     'aiLayer',
    split_letter: 'splitLetter',
    base64_hex:   'base64Hex',
    unicode_norm: 'unicodeNorm',
    rot13:        'rot13',
  };

  const merged = { ...DEFAULT_POLICIES };

  for (const [apiKey, uiKey] of Object.entries(keyMap)) {
    if (apiKey in apiData && uiKey in merged) {
      merged[uiKey] = {
        ...merged[uiKey],
        enabled: Boolean(apiData[apiKey]),
      };
    }
  }

  return merged;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function usePolicies() {
  const [policies, setPolicies] = useState(DEFAULT_POLICIES);
  const [updating, setUpdating] = useState(null);
  const [loading,  setLoading]  = useState(true);

  // Load policies from API on mount
  useEffect(() => {
    async function load() {
      try {
        const data = await fetchPolicies();
        // data may be the raw flat dict from the backend
        if (data && typeof data === 'object') {
          setPolicies(mergePoliciesFromAPI(data));
        }
      } catch {
        // Keep local defaults — backend may be offline
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const togglePolicy = useCallback(async (key) => {
    const newValue = !policies[key]?.enabled;

    // Optimistic update
    setPolicies(prev => ({
      ...prev,
      [key]: { ...prev[key], enabled: newValue },
    }));
    setUpdating(key);

    try {
      // Convert camelCase key back to snake_case for the API
      const apiKeyMap = {
        franco:      'franco',
        nationalId:  'national_id',
        slang:       'slang',
        aiLayer:     'ai_layer',
        splitLetter: 'split_letter',
        base64Hex:   'base64_hex',
        unicodeNorm: 'unicode_norm',
        rot13:       'rot13',
      };
      const apiKey = apiKeyMap[key] ?? key;
      await updatePolicy(apiKey, newValue);
    } catch {
      // Rollback on error
      setPolicies(prev => ({
        ...prev,
        [key]: { ...prev[key], enabled: !newValue },
      }));
    } finally {
      setUpdating(null);
    }
  }, [policies]);

  const activeCount = Object.values(policies).filter(p => p.enabled).length;

  return { policies, togglePolicy, updating, loading, activeCount };
}