import { useEffect, useRef, type RefObject } from "react";

// Data streaming toward the policy line. Grey packets are trusted and pass
// the line, turning bright once checked. Amber packets are untrusted: with the
// policy on they stop at the line in a scarlet flash; with it off they leak
// through. Clicking the field injects a burst of untrusted packets.
const PITCH = 16;
const BAR = 6;
const UNTRUSTED_SHARE = 0.18;
const FLASH_MS = 450;

const TRUSTED = "rgba(236, 234, 228, 0.28)";
const CHECKED = "rgba(236, 234, 228, 0.78)";
const TAINT = "rgba(245, 180, 42, 0.95)";

interface Packet {
  y: number;
  len: number;
  bad: boolean;
  /** Counted as a leak once it crosses an unguarded line. */
  leaked?: boolean;
}

interface Column {
  x: number;
  speed: number;
  packets: Packet[];
}

interface Flash {
  x: number;
  age: number;
}

export type FlowEvent = "stopped" | "leaked";

const rand = (min: number, max: number) => min + Math.random() * (max - min);

function packet(y: number, lineY: number): Packet {
  const len = rand(18, 84);
  // Packets that start below the line have already been checked.
  return { y, len, bad: y + len < lineY && Math.random() < UNTRUSTED_SHARE };
}

interface Props {
  lineRef: RefObject<HTMLElement | null>;
  /** Element whose clicks inject untrusted data. */
  hostRef: RefObject<HTMLElement | null>;
  guarded: boolean;
  onEvent: (e: FlowEvent) => void;
}

export function FlowField({ lineRef, hostRef, guarded, onEvent }: Props) {
  const ref = useRef<HTMLCanvasElement>(null);
  const guardedRef = useRef(guarded);
  const onEventRef = useRef(onEvent);
  guardedRef.current = guarded;
  onEventRef.current = onEvent;

  useEffect(() => {
    const canvas = ref.current!;
    const host = hostRef.current!;
    const ctx = canvas.getContext("2d")!;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let columns: Column[] = [];
    let flashes: Flash[] = [];
    let w = 0;
    let h = 0;
    let frame = 0;
    let last = 0;
    let running = false;

    const lineY = () => {
      const line = lineRef.current;
      if (!line) return h * 0.55;
      return line.getBoundingClientRect().top - canvas.getBoundingClientRect().top;
    };

    const setup = () => {
      const dpr = window.devicePixelRatio || 1;
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const ly = lineY();
      columns = [];
      for (let x = PITCH / 2; x < w; x += PITCH) {
        const packets: Packet[] = [];
        // Fill the whole height so the first frame is already busy.
        for (let y = rand(-120, 0); y < h; y += rand(60, 170)) packets.push(packet(y, ly));
        columns.push({ x, speed: rand(0.035, 0.11), packets });
      }
      flashes = [];
    };

    const render = (dt: number) => {
      const ly = lineY();
      const guard = guardedRef.current;
      ctx.clearRect(0, 0, w, h);

      for (const col of columns) {
        for (const p of col.packets) p.y += col.speed * dt;

        col.packets = col.packets.filter((p) => {
          if (p.bad && guard && p.y >= ly && !p.leaked) {
            flashes.push({ x: col.x, age: 0 });
            onEventRef.current("stopped");
            return false;
          }
          if (p.bad && !guard && !p.leaked && p.y + p.len > ly) {
            p.leaked = true;
            onEventRef.current("leaked");
          }
          return p.y < h;
        });

        const top = col.packets[0];
        if (!top || top.y > rand(40, 150)) col.packets.unshift(packet(-rand(20, 90), ly));

        for (const p of col.packets) {
          const start = p.y;
          if (p.bad) {
            const end = guard && !p.leaked ? Math.min(p.y + p.len, ly) : p.y + p.len;
            ctx.fillStyle = TAINT;
            ctx.fillRect(col.x - BAR / 2, start, BAR, end - start);
            continue;
          }
          const end = p.y + p.len;
          if (start < ly) {
            ctx.fillStyle = TRUSTED;
            ctx.fillRect(col.x - BAR / 2, start, BAR, Math.min(end, ly) - start);
          }
          if (end > ly) {
            ctx.fillStyle = CHECKED;
            const from = Math.max(start, ly + 3);
            ctx.fillRect(col.x - BAR / 2, from, BAR, end - from);
          }
        }
      }

      for (const f of flashes) {
        f.age += dt;
        const t = f.age / FLASH_MS;
        ctx.fillStyle = `rgba(255, 45, 31, ${Math.max(1 - t, 0)})`;
        const spread = 5 + t * 16;
        ctx.fillRect(f.x - spread, ly - 3, spread * 2, 6);
      }
      flashes = flashes.filter((f) => f.age < FLASH_MS);
    };

    const loop = (now: number) => {
      render(last ? Math.min(now - last, 50) : 16);
      last = now;
      frame = requestAnimationFrame(loop);
    };

    const start = () => {
      if (running) return;
      running = true;
      last = 0;
      frame = requestAnimationFrame(loop);
    };

    // Inject a burst of untrusted packets around the click.
    const inject = (ev: PointerEvent) => {
      if ((ev.target as Element).closest("a, button, input, label, code, pre")) return;
      const rect = canvas.getBoundingClientRect();
      const x = ev.clientX - rect.left;
      const ly = lineY();
      const y = Math.min(ev.clientY - rect.top, ly - 40);
      for (const col of columns) {
        if (Math.abs(col.x - x) > PITCH * 3) continue;
        const len = rand(40, 110);
        col.packets.push({ y: y - len - rand(0, 60), len, bad: true });
        col.packets.sort((a, b) => a.y - b.y);
      }
      // Reduced motion: animate only while the injected data is in flight.
      if (still) {
        start();
        setTimeout(() => {
          cancelAnimationFrame(frame);
          running = false;
        }, 4000);
      }
    };

    const observer = new ResizeObserver(() => {
      setup();
      render(0);
    });
    observer.observe(canvas);
    host.addEventListener("pointerdown", inject);
    setup();
    render(0);
    if (!still) start();
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      host.removeEventListener("pointerdown", inject);
    };
  }, [lineRef, hostRef]);

  return <canvas ref={ref} className="flowfield" aria-hidden />;
}
