/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html", "./static/js/**/*.js"],
  safelist: [
    "border-amber-300/20",
    "text-amber-200",
    "border-emerald-300/20",
    "text-emerald-200"
  ],
  theme: {
    extend: {
      colors: {
        void: "#02021f",
        nebula: {
          50: "#f6f1ff",
          100: "#eadcff",
          200: "#d9bdff",
          300: "#c18cff",
          400: "#aa55f7",
          500: "#912ee5",
          600: "#751cc1",
          700: "#570d91",
          800: "#420b6b",
          900: "#310a4e"
        },
        orbit: { 300: "#78ccff", 400: "#21a8ff", 500: "#0b8fe8", 600: "#066cbd" },
        plasma: { 300: "#9aa6ff", 400: "#6875ff", 500: "#1729ff", 600: "#111ed0" }
      },
      fontFamily: { sans: ["Noto Sans", "ui-sans-serif", "system-ui", "sans-serif"] },
      fontWeight: { hairline: "100", extralight: "200" },
      boxShadow: {
        glow: "0 0 35px rgba(145,46,229,.18)",
        orbit: "0 0 28px rgba(33,168,255,.15)"
      },
      backgroundImage: {
        "galaxy-radial": "radial-gradient(circle at top right, rgba(145,46,229,.22), transparent 40%), radial-gradient(circle at bottom left, rgba(33,168,255,.16), transparent 38%)"
      }
    }
  },
  plugins: []
};
