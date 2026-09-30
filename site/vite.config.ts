import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Relative base so the build works from any path (e.g. GitHub Pages /aegis/).
export default defineConfig({
  base: "./",
  plugins: [react()],
  // Top-level await loads the policy engine before the first render.
  build: { target: "es2022" },
});
