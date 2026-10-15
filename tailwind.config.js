/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        portal: {
          bg: '#020617',        // slate-950
          surface: '#0f172a',   // slate-900
          card: '#1e293b',      // slate-800
          border: '#334155',    // slate-700
        },
        primary: {
          DEFAULT: '#29c7ff',   // accent blue
          hover: '#0ea5e9',     // sky-500
          light: '#7dd3fc',     // sky-300
        },
      },
      boxShadow: {
        'panel': '0 4px 16px rgba(0, 0, 0, 0.4)',
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.4rem',
      },
    },
  },
  plugins: [],
}
