import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        "ritma-bg-void": "#0A0F1F",
        "ritma-graphite": "#0D1117",
        "ritma-orange": "#FF6A00",
        "ritma-ember": "#F5A623",
        "ritma-teal": "#1FE4A7",
        "ritma-blue": "#4CC3FF",
        "ritma-amber": "#FFC247",
        "ritma-red": "#FF3F3F",
      },
      borderRadius: {
        "ritma-card": "10px",
        "ritma-button": "8px",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
