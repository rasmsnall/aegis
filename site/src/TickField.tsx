import { useEffect, useRef } from "react";

// Animated field of vertical dashes whose lengths ripple outward from a few
// centres, drawn on a canvas behind the hero.
const COL = 26;
const ROW = 44;
const CENTRES = [
  [0.2, 0.55],
  [0.5, 0.35],
  [0.8, 0.6],
];

export function TickField() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current!;
    const ctx = canvas.getContext("2d")!;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let frame = 0;
    let w = 0;
    let h = 0;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      const phase = t / 1400;
      for (let x = COL / 2; x < w; x += COL) {
        for (let y = ROW / 2; y < h; y += ROW) {
          let v = 0;
          for (const [cx, cy] of CENTRES) {
            const d = Math.hypot(x - cx * w, y - cy * h);
            v = Math.max(v, Math.cos(d / 58 - phase));
          }
          if (v < 0.4) continue;
          const len = 8 + (v - 0.4) * 34;
          ctx.fillStyle = `rgba(150, 160, 175, ${0.2 + v * 0.5})`;
          ctx.fillRect(x, y - len / 2, 2, len);
        }
      }
      if (!still) frame = requestAnimationFrame(draw);
    };

    const observer = new ResizeObserver(() => {
      resize();
      if (still) draw(0);
    });
    observer.observe(canvas);
    resize();
    frame = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, []);

  return <canvas ref={ref} className="tickfield" aria-hidden />;
}
