// Landing page navigation: deep-link the URL hash to the section in view and
// switch the Quick Start example tabs. (Moved out of an inline <script>: the
// page's Content-Security-Policy allows scripts from this origin only.)

const sections = document.querySelectorAll('.page-section[id]');
const navLinks = document.querySelectorAll('.sdn-header-links .nav-link');

const observer = new IntersectionObserver((entries) => {
  // The account view owns #account/<section> while it is open.
  if (location.hash.startsWith('#account/')) return;
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      const id = entry.target.id;
      // Update hash without scrolling
      history.replaceState(null, '', id === 'hero' ? '#' : `#${id}`);
      navLinks.forEach((link) => {
        link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
      });
    }
  });
}, { threshold: 0.3 });

sections.forEach((section) => observer.observe(section));

document.querySelectorAll('.example-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    const target = tab.dataset.example;
    document.querySelectorAll('.example-tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.example-code').forEach((c) => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`example-code-${target}`)?.classList.add('active');
  });
});
