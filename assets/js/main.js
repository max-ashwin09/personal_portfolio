/**
* Template Name: Craftivo
* Template URL: https://bootstrapmade.com/craftivo-bootstrap-portfolio-template/
* Updated: Oct 04 2025 with Bootstrap v5.3.8
* Author: BootstrapMade.com
* License: https://bootstrapmade.com/license/
*/

(function() {
  "use strict";

  /**
   * Automatic System Theme (follows device Dark / Light preference)
   */
  const systemDarkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  function applySystemTheme() {
    const resolved = systemDarkQuery.matches ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', resolved);
  }

  function initSystemTheme() {
    applySystemTheme();

    if (typeof systemDarkQuery.addEventListener === 'function') {
      systemDarkQuery.addEventListener('change', applySystemTheme);
    } else if (typeof systemDarkQuery.addListener === 'function') {
      systemDarkQuery.addListener(applySystemTheme);
    }
  }

  initSystemTheme();

  let scrollListenersAttached = false;
  let glightboxInstance = null;

  /**
   * Apply .scrolled class to the body as the page is scrolled down
   */
  function toggleScrolled() {
    const selectBody = document.querySelector('body');
    const selectHeader = document.querySelector('#header');
    if (!selectHeader) return;
    if (!selectHeader.classList.contains('scroll-up-sticky') && !selectHeader.classList.contains('sticky-top') && !selectHeader.classList.contains('fixed-top')) return;
    window.scrollY > 100 ? selectBody.classList.add('scrolled') : selectBody.classList.remove('scrolled');
  }

  /**
   * Preloader
   */
  function hidePreloader() {
    const preloader = document.querySelector('#preloader');
    if (preloader) {
      preloader.remove();
    }
  }

  /**
   * Scroll top button
   */
  function toggleScrollTop() {
    const scrollTop = document.querySelector('.scroll-top');
    if (scrollTop) {
      window.scrollY > 100 ? scrollTop.classList.add('active') : scrollTop.classList.remove('active');
    }
  }

  /**
   * Navmenu Scrollspy
   */
  function navmenuScrollspy() {
    const navmenulinks = document.querySelectorAll('.navmenu a');
    navmenulinks.forEach(navmenulink => {
      if (!navmenulink.hash) return;
      const section = document.querySelector(navmenulink.hash);
      if (!section) return;
      const position = window.scrollY + 200;
      if (position >= section.offsetTop && position <= (section.offsetTop + section.offsetHeight)) {
        document.querySelectorAll('.navmenu a.active').forEach(link => link.classList.remove('active'));
        navmenulink.classList.add('active');
      } else {
        navmenulink.classList.remove('active');
      }
    });
  }

  /**
   * Initialize all interactive UI modules on unlocked DOM
   */
  function initPortfolioApp() {
    hidePreloader();

    const scrollTop = document.querySelector('.scroll-top');
    if (scrollTop && !scrollTop.dataset.bound) {
      scrollTop.dataset.bound = '1';
      scrollTop.addEventListener('click', (e) => {
        e.preventDefault();
        window.scrollTo({
          top: 0,
          behavior: 'smooth'
        });
      });
    }

    if (!scrollListenersAttached) {
      scrollListenersAttached = true;
      document.addEventListener('scroll', toggleScrolled);
      document.addEventListener('scroll', toggleScrollTop);
      document.addEventListener('scroll', navmenuScrollspy);
    }

    toggleScrolled();
    toggleScrollTop();
    navmenuScrollspy();

    /**
     * Mobile nav toggle
     */
    const mobileNavToggleBtn = document.querySelector('.mobile-nav-toggle');
    function mobileNavToogle() {
      document.querySelector('body').classList.toggle('mobile-nav-active');
      if (mobileNavToggleBtn) {
        mobileNavToggleBtn.classList.toggle('bi-list');
        mobileNavToggleBtn.classList.toggle('bi-x');
      }
    }
    if (mobileNavToggleBtn && !mobileNavToggleBtn.dataset.bound) {
      mobileNavToggleBtn.dataset.bound = '1';
      mobileNavToggleBtn.addEventListener('click', mobileNavToogle);
    }

    document.querySelectorAll('#navmenu a').forEach(navmenu => {
      if (navmenu.dataset.bound) return;
      navmenu.dataset.bound = '1';
      navmenu.addEventListener('click', () => {
        if (document.querySelector('.mobile-nav-active')) {
          mobileNavToogle();
        }
      });
    });

    document.querySelectorAll('.navmenu .toggle-dropdown').forEach(navmenu => {
      if (navmenu.dataset.bound) return;
      navmenu.dataset.bound = '1';
      navmenu.addEventListener('click', function(e) {
        e.preventDefault();
        this.parentNode.classList.toggle('active');
        this.parentNode.nextElementSibling.classList.toggle('dropdown-active');
        e.stopImmediatePropagation();
      });
    });

    /**
     * Animation on scroll function and init
     */
    function aosInit() {
      if (typeof AOS === 'undefined') return;
      AOS.init({
        duration: 600,
        easing: 'ease-in-out',
        once: true,
        mirror: false
      });
      if (typeof AOS.refreshHard === 'function') {
        AOS.refreshHard();
      }
    }
    aosInit();

    /**
     * Init typed.js
     */
    const selectTyped = document.querySelector('.typed');
    if (selectTyped && typeof Typed !== 'undefined' && !selectTyped.dataset.typedInit) {
      selectTyped.dataset.typedInit = '1';
      const nextCursor = selectTyped.nextElementSibling;
      if (nextCursor && nextCursor.classList.contains('typed-cursor')) {
        nextCursor.remove();
      }
      let typed_strings = selectTyped.getAttribute('data-typed-items') || '';
      typed_strings = typed_strings.split(',');
      new Typed('.typed', {
        strings: typed_strings,
        loop: true,
        typeSpeed: 100,
        backSpeed: 50,
        backDelay: 2000
      });
    }

    /**
     * Animate the skills items on reveal
     */
    const skillsAnimation = document.querySelectorAll('.skills-animation');
    if (typeof Waypoint !== 'undefined') {
      skillsAnimation.forEach((item) => {
        if (item.dataset.waypointInit) return;
        item.dataset.waypointInit = '1';
        new Waypoint({
          element: item,
          offset: '80%',
          handler: function() {
            const progress = item.querySelectorAll('.progress .progress-bar');
            progress.forEach(el => {
              el.style.width = el.getAttribute('aria-valuenow') + '%';
            });
          }
        });
      });
      if (typeof Waypoint.refreshAll === 'function') {
        Waypoint.refreshAll();
      }
    }

    /**
     * Initiate glightbox
     */
    if (typeof GLightbox !== 'undefined') {
      if (glightboxInstance && typeof glightboxInstance.destroy === 'function') {
        glightboxInstance.destroy();
      }
      glightboxInstance = GLightbox({
        selector: '.glightbox'
      });
    }

    /**
     * Init isotope layout and filters
     */
    if (typeof Isotope !== 'undefined' && typeof imagesLoaded !== 'undefined') {
      document.querySelectorAll('.isotope-layout').forEach(function(isotopeItem) {
        if (isotopeItem.dataset.isotopeInit) return;
        isotopeItem.dataset.isotopeInit = '1';
        const layout = isotopeItem.getAttribute('data-layout') ?? 'masonry';
        const filter = isotopeItem.getAttribute('data-default-filter') ?? '*';
        const sort = isotopeItem.getAttribute('data-sort') ?? 'original-order';

        let initIsotope;
        imagesLoaded(isotopeItem.querySelector('.isotope-container'), function() {
          initIsotope = new Isotope(isotopeItem.querySelector('.isotope-container'), {
            itemSelector: '.isotope-item',
            layoutMode: layout,
            filter: filter,
            sortBy: sort
          });
        });

        isotopeItem.querySelectorAll('.isotope-filters li').forEach(function(filters) {
          filters.addEventListener('click', function() {
            isotopeItem.querySelector('.isotope-filters .filter-active').classList.remove('filter-active');
            this.classList.add('filter-active');
            if (initIsotope) {
              initIsotope.arrange({
                filter: this.getAttribute('data-filter')
              });
            }
            aosInit();
          }, false);
        });
      });
    }

    /**
     * Init swiper sliders
     */
    if (typeof Swiper !== 'undefined') {
      document.querySelectorAll('.init-swiper').forEach(function(swiperElement) {
        if (swiperElement.dataset.swiperInit) return;
        swiperElement.dataset.swiperInit = '1';
        const config = JSON.parse(
          swiperElement.querySelector('.swiper-config').innerHTML.trim()
        );
        if (swiperElement.classList.contains('swiper-tab') && typeof initSwiperWithCustomPagination === 'function') {
          initSwiperWithCustomPagination(swiperElement, config);
        } else {
          new Swiper(swiperElement, config);
        }
      });
    }

    /**
     * Portfolio Contact Form (PHP endpoint with static-host mailto fallback)
     */
    document.querySelectorAll('.portfolio-contact-form').forEach((form) => {
      if (form.dataset.bound) return;
      form.dataset.bound = '1';
      form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const loadingEl = form.querySelector('.loading');
        const errorEl = form.querySelector('.error-message');
        const sentEl = form.querySelector('.sent-message');
        const fallbackEmail = form.getAttribute('data-fallback-email') || 'mr.vivek7009@gmail.com';
        const action = form.getAttribute('action');

        loadingEl.classList.add('d-block');
        errorEl.classList.remove('d-block');
        sentEl.classList.remove('d-block');

        const formData = new FormData(form);
        const name = String(formData.get('name') || '').trim();
        const email = String(formData.get('email') || '').trim();
        const subject = String(formData.get('subject') || '').trim();
        const message = String(formData.get('message') || '').trim();

        const openMailtoFallback = () => {
          const mailSubject = encodeURIComponent(subject || `Portfolio Inquiry from ${name}`);
          const mailBody = encodeURIComponent(`Name: ${name}\nEmail: ${email}\n\n${message}`);
          loadingEl.classList.remove('d-block');
          sentEl.textContent = `Opening your email app to send this message to ${fallbackEmail}.`;
          sentEl.classList.add('d-block');
          window.location.href = `mailto:${fallbackEmail}?subject=${mailSubject}&body=${mailBody}`;
          form.reset();
        };

        if (!action) {
          openMailtoFallback();
          return;
        }

        try {
          const response = await fetch(action, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
          });
          const text = await response.text();
          if (response.ok && text.trim() === 'OK') {
            loadingEl.classList.remove('d-block');
            sentEl.textContent = 'Your message has been sent. Thank you!';
            sentEl.classList.add('d-block');
            form.reset();
          } else {
            openMailtoFallback();
          }
        } catch (err) {
          openMailtoFallback();
        }
      });
    });

    /**
     * Scroll to hash target when opening deep links after unlock
     */
    if (window.location.hash) {
      const target = document.querySelector(window.location.hash);
      if (target) {
        setTimeout(() => {
          const scrollMarginTop = getComputedStyle(target).scrollMarginTop || '0';
          window.scrollTo({
            top: target.offsetTop - (parseInt(scrollMarginTop, 10) || 0),
            behavior: 'smooth'
          });
        }, 120);
      }
    }
  }

  window.initPortfolioApp = initPortfolioApp;

  const isGatedPage = Boolean(document.body && document.body.hasAttribute('data-gate-page'));
  if (!isGatedPage) {
    window.addEventListener('load', initPortfolioApp);
  } else {
    window.addEventListener('load', hidePreloader);
  }

})();
