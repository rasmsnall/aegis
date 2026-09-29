import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Relative base so the build works from any path (e.g. GitHub Pages /aegis/).
export default defineConfig({
  base: "./",
  plugins: [react()],
});
