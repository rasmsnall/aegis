import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.tsx";
import { initEngine } from "./engine.ts";
import "./styles.css";

// The playground decides calls with the Rust engine, so load it first. If it
// fails, the rest of the page still renders and the playground says so.
await initEngine().catch((e) => console.error("aegis: could not load the policy engine", e));

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
