/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["'IBM Plex Mono'", "'Fira Code'", "monospace"],
        display: ["'DM Sans'", "system-ui", "sans-serif"],
      },
      colors: {
        zinc: {
          925: "#141414",
          950: "#0a0a0a",
        },
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan": "scan 2s linear infinite",
        "glow": "glow 2s ease-in-out infinite alternate",
      },
      keyframes: {
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        glow: {
          from: { boxShadow: "0 0 5px rgb(16 185 129 / 0.3)" },
          to: { boxShadow: "0 0 20px rgb(16 185 129 / 0.6)" },
        },
      },
      boxShadow: {
        "glow-emerald": "0 0 20px rgb(16 185 129 / 0.15)",
        "glow-rose": "0 0 20px rgb(244 63 94 / 0.15)",
        "glow-blue": "0 0 20px rgb(59 130 246 / 0.15)",
        "glow-violet": "0 0 20px rgb(139 92 246 / 0.15)",
      },
    },
  },
  plugins: [],
};
