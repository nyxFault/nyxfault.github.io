/* Particle network background — skipped when prefers-reduced-motion: reduce */
(function () {
  'use strict';

  const mqReduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  if (mqReduce.matches) return;

  function isDarkMode() {
    const m = document.documentElement.getAttribute('data-mode');
    if (m === 'dark') return true;
    if (m === 'light') return false;
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function palette() {
    if (isDarkMode()) {
      return {
        dot: [56, 232, 208],
        line: [56, 232, 208],
        dotAlpha: 0.35,
        lineAlpha: 0.08,
      };
    }
    return {
      dot: [0, 120, 115],
      line: [0, 100, 95],
      dotAlpha: 0.22,
      lineAlpha: 0.05,
    };
  }

  const canvas = document.createElement('canvas');
  canvas.id = 'cyber-particles-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  document.body.prepend(canvas);

  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  let w = 0;
  let h = 0;
  let dpr = 1;
  let particles = [];
  let raf = 0;
  let pal = palette();

  const LINK_DIST = 110;
  const LINK_DIST_SQ = LINK_DIST * LINK_DIST;
  const BASE_SPEED = 0.22;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = window.innerWidth;
    h = window.innerHeight;
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    initParticles();
  }

  function particleCount() {
    return Math.min(140, Math.max(48, Math.floor((w * h) / 12000)));
  }

  function initParticles() {
    const n = particleCount();
    particles = [];
    for (let i = 0; i < n; i++) {
      particles.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * BASE_SPEED * 2,
        vy: (Math.random() - 0.5) * BASE_SPEED * 2,
        r: Math.random() * 1.4 + 0.6,
        pulse: Math.random() * Math.PI * 2,
      });
    }
  }

  function step() {
    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      p.pulse += 0.012;
      if (p.x < -20) p.x = w + 20;
      if (p.x > w + 20) p.x = -20;
      if (p.y < -20) p.y = h + 20;
      if (p.y > h + 20) p.y = -20;
    }
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);
    const { dot, line, dotAlpha, lineAlpha } = pal;

    for (let i = 0; i < particles.length; i++) {
      const a = particles[i];
      for (let j = i + 1; j < particles.length; j++) {
        const b = particles[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < LINK_DIST_SQ) {
          const t = 1 - d2 / LINK_DIST_SQ;
          ctx.strokeStyle = `rgba(${line[0]}, ${line[1]}, ${line[2]}, ${t * lineAlpha})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    for (const p of particles) {
      const tw = 0.85 + Math.sin(p.pulse) * 0.15;
      ctx.fillStyle = `rgba(${dot[0]}, ${dot[1]}, ${dot[2]}, ${dotAlpha * tw})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function loop() {
    step();
    draw();
    raf = window.requestAnimationFrame(loop);
  }

  const modeObserver = new MutationObserver(() => {
    pal = palette();
  });
  modeObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-mode'],
  });

  mqReduce.addEventListener('change', () => {
    if (mqReduce.matches) {
      window.cancelAnimationFrame(raf);
      canvas.remove();
      modeObserver.disconnect();
    }
  });

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      window.cancelAnimationFrame(raf);
      raf = 0;
    } else if (!raf) {
      raf = window.requestAnimationFrame(loop);
    }
  });

  resize();
  pal = palette();
  raf = window.requestAnimationFrame(loop);
})();
