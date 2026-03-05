# ArabGuard Dashboard

> Enterprise React frontend for the ArabGuard AI security platform.

## 📁 Project Structure

```
arabguard-dashboard/
├── .env.example                     ← Copy to .env and fill values
├── index.html
├── vite.config.js
├── tailwind.config.js
│
└── src/
    ├── main.jsx                     ← Entry point
    ├── App.jsx                      ← Router + layout wiring
    │
    ├── styles/
    │   └── globals.css              ← Global CSS + Tailwind + CSS variables
    │
    ├── data/
    │   └── mockData.js              ← Realistic Franco-Arabic mock data
    │
    ├── services/
    │   └── api.js                   ← Axios client → FastAPI + HuggingFace
    │
    ├── hooks/
    │   ├── useGuard.js              ← Live feed, scanner, polling, mock fallback
    │   └── usePolicies.js           ← Guardrail toggle state
    │
    ├── components/
    │   ├── common/
    │   │   ├── Badges.jsx           ← RiskBadge, StatusBadge, ScoreBadge, AiConfBadge
    │   │   ├── Buttons.jsx          ← Button, IconButton
    │   │   ├── Card.jsx             ← Card, CardHeader, CardBody, StatCard
    │   │   ├── Input.jsx            ← Input, SearchInput, Textarea
    │   │   └── Toggle.jsx           ← Toggle switch
    │   │
    │   ├── layout/
    │   │   ├── Sidebar.jsx          ← Nav with React Router NavLinks
    │   │   └── TopNavbar.jsx        ← Page title + live counter + notifications
    │   │
    │   └── dashboard/
    │       ├── ThreatTable.jsx      ← Live feed → GuardResult rows + expand
    │       ├── Charts.jsx           ← Radar, Bar, Area charts (Recharts)
    │       ├── GuardrailToggles.jsx ← Policy toggles + API schema preview
    │       ├── PIIVisualizer.jsx    ← Before/After PII redaction
    │       └── ScannerPanel.jsx     ← Real-time text analysis widget
    │
    └── pages/
        ├── Dashboard.jsx            ← Main command center
        ├── Logs.jsx                 ← Full threat log table
        ├── Analytics.jsx            ← Charts-only view
        ├── Queue.jsx                ← Human-in-the-loop review
        ├── Docs.jsx                 ← API integration guide
        └── Settings.jsx             ← Policies + API config
```

## 🚀 Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
```
Edit `.env`:
```
VITE_API_BASE_URL=http://localhost:8000    # Your FastAPI backend
VITE_HF_API_TOKEN=hf_xxxxx                # From huggingface.co/settings/tokens
VITE_ENABLE_MOCK_DATA=true                 # false = live backend required
```

### 3. Run dev server
```bash
npm run dev
# → http://localhost:3000
```

## 🔗 API Integration

### FastAPI endpoint expected
```python
@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    result = guard.analyze(req.text)
    return result.to_dict()
```

### GuardResult shape (from `api.js`)
| Field | Type | Description |
|-------|------|-------------|
| `decision` | `"SAFE"│"FLAG"│"BLOCKED"` | Final decision |
| `score` | `int 0–300` | Aggregate risk score |
| `is_blocked` | `bool` | True if BLOCKED |
| `ai_confidence` | `float│null` | MARBERT confidence |
| `ai_prediction` | `0│1│null` | 0=safe, 1=malicious |
| `matched_pattern` | `string│null` | First matching regex |
| `pipeline_steps` | `object` | Per-stage scores |

### Data flow
```
User types → ScannerPanel
  → useGuard.scan(text)
    → api.analyzeText(text) [POST /analyze]
      → FastAPI → ArabGuard pipeline → GuardResult
    → setScanResult(result)
  → result rendered in ScannerPanel
  → threat added to live ThreatTable
```

## 🧠 Model Details
- **Model**: `d12o6aa/ArabGuard` on Hugging Face
- **Base**: `UBC-NLP/MARBERT` (Arabic BERT)
- **F1**: 0.97 · **Precision**: 0.96 · **Recall**: 0.98
- **Labels**: `LABEL_0` = Safe, `LABEL_1` = Malicious

## 📦 Dependencies
| Package | Purpose |
|---------|---------|
| `react-router-dom` | Client-side routing |
| `framer-motion` | Page + row animations |
| `axios` | HTTP client (FastAPI + HF) |
| `recharts` | Radar, Bar, Area charts |
| `lucide-react` | Icon system |
| `date-fns` | Timestamp formatting |
| `clsx` | Conditional classnames |
