// VAULTSCAN brand tokens. Source: BrandGuidelines v1.0.
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        inter: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      colors: {
        // VAULTSCAN brand
        'orange-primary':   '#FF6B00',
        'orange-secondary': '#FF8C00',
        'bg-void':          '#0A0A0A',
        'bg-deep':          '#111111',
        'bg-surface':       '#1A1A1A',
        'border-subtle':    '#2A2A2A',
        'text-primary':     '#F0F0F0',
        'text-muted':       '#8A8A8A',
        'status-critical':  '#FF2D2D',
        'status-high':      '#FF6B00',
        'status-medium':    '#FFB800',
        'status-low':       '#00FF88',
      },
      letterSpacing: {
        'widest-2': '0.2em',
        'widest-3': '0.3em',
        'widest-4': '0.4em',
        'widest-5': '0.5em',
      },
      animation: {
        'pulse-orange': 'pulseOrange 1.5s ease-in-out infinite',
        'sweep':        'sweep 1.6s linear infinite',
      },
      keyframes: {
        pulseOrange: {
          '0%,100%': { boxShadow: '0 0 0 0 rgba(255,107,0,0.6)' },
          '50%':     { boxShadow: '0 0 16px 4px rgba(255,107,0,0.0)' },
        },
        sweep: {
          '0%':   { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
    },
  },
  plugins: [],
};
