/**
 * Sidebar tab links: replay a short click feedback animation (scan sweep).
 */
(function () {
  const CLASS = 'cyber-nav-sweep';
  const DURATION_MS = 450;

  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;

  const nav = sidebar.querySelector('nav');
  if (!nav) return;

  const prefersReduced =
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function play(el) {
    if (prefersReduced) return;
    el.classList.remove(CLASS);
    void el.offsetWidth;
    el.classList.add(CLASS);

    window.clearTimeout(el._cyberNavSweepTimer);
    el._cyberNavSweepTimer = window.setTimeout(function () {
      el.classList.remove(CLASS);
    }, DURATION_MS);
  }

  function skipModifiers(e) {
    return e.metaKey || e.ctrlKey || e.shiftKey || e.altKey;
  }

  nav.querySelectorAll('a.nav-link[href]').forEach(function (a) {
    a.addEventListener(
      'pointerdown',
      function (e) {
        if (e.button !== 0 || skipModifiers(e)) return;
        play(a);
      },
      { passive: true }
    );

    a.addEventListener(
      'keydown',
      function (e) {
        if (e.key !== 'Enter' || skipModifiers(e)) return;
        play(a);
      },
      { passive: true }
    );
  });
})();
