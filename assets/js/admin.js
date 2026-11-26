/**
 * VCRYPT Owner Access Console
 * Manages real-time visitor approvals, rejections, revocations, and passcode/cloud settings.
 */

(function () {
  "use strict";

  const systemDarkQuery = window.matchMedia("(prefers-color-scheme: dark)");
  function applyTheme() {
    document.documentElement.setAttribute("data-theme", systemDarkQuery.matches ? "dark" : "light");
  }
  applyTheme();
  if (typeof systemDarkQuery.addEventListener === "function") {
    systemDarkQuery.addEventListener("change", applyTheme);
  }

  const cfg = window.VCRYPT_GATE_CONFIG || {};
  const apiBase = cfg.localApiBase || "/api";

  const modePill = document.getElementById("adminModePill");
  const liveDot = document.getElementById("adminLiveIndicator");
  const sessionTimerEl = document.getElementById("adminSessionTimer");
  const sessionTimerTextEl = document.getElementById("adminSessionTimerText");
  const logoutBtn = document.getElementById("adminLogoutBtn");

  const loadingPanel = document.getElementById("adminLoadingPanel");
  const setupPanel = document.getElementById("adminSetupPanel");
  const loginPanel = document.getElementById("adminLoginPanel");
  const firebasePanel = document.getElementById("adminFirebasePanel");
  const unconfiguredPanel = document.getElementById("adminUnconfiguredPanel");
  const dashboard = document.getElementById("adminDashboard");

  const setupForm = document.getElementById("adminSetupForm");
  const setupError = document.getElementById("setupError");
  const loginForm = document.getElementById("adminLoginForm");
  const loginError = document.getElementById("loginError");
  const loginNotice = document.getElementById("loginNotice");
  const firebaseGoogleBtn = document.getElementById("firebaseGoogleLoginBtn");
  const firebaseAuthError = document.getElementById("firebaseAuthError");
  const firebaseAdminEmailLabel = document.getElementById("firebaseAdminEmailLabel");

  const statTotal = document.getElementById("statTotal");
  const statPending = document.getElementById("statPending");
  const statApproved = document.getElementById("statApproved");
  const statBlocked = document.getElementById("statBlocked");

  const requestsContainer = document.getElementById("adminRequestsContainer");
  const searchInput = document.getElementById("adminSearchInput");
  const refreshBtn = document.getElementById("adminRefreshBtn");
  const filterTabs = document.querySelectorAll(".filter-tab");

  const localPasscodeCard = document.getElementById("localPasscodeCard");
  const changePasscodeForm = document.getElementById("changePasscodeForm");
  const passcodeMsg = document.getElementById("passcodeMsg");

  const vaultKeyPreview = document.getElementById("vaultKeyPreview");
  const toggleKeyBtn = document.getElementById("toggleKeyBtn");
  const copyKeyBtn = document.getElementById("copyKeyBtn");

  const DEFAULT_IDLE_TIMEOUT_MS = 2 * 60 * 1000;
  const FB_CONSOLE_LOCK_KEY = "vcrypt_fb_console_unlocked";

  let modeDriver = null; // 'local' | 'firebase'
  let allRequests = [];
  let activeFilter = "all";
  let vaultKeyRaw = "";
  let keyVisible = false;
  let adminEventSource = null;
  let firebaseCtx = null;
  let unsubscribeList = null;

  let isConsoleUnlocked = false;
  let adminTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
  let sessionExpiresAt = 0;
  let lastLocalActivityAt = 0;
  let lastServerTouchAt = 0;
  let sessionTicker = null;
  let pendingLoginNotice = "";

  function hideAllSections() {
    [loadingPanel, setupPanel, loginPanel, firebasePanel, unconfiguredPanel, dashboard].forEach((el) => {
      if (el) el.hidden = true;
    });
  }

  function showMessage(el, msg) {
    if (!el) return;
    if (!msg) {
      el.hidden = true;
      el.textContent = "";
      return;
    }
    el.textContent = msg;
    el.hidden = false;
  }

  function formatCountdown(ms) {
    const totalSeconds = Math.max(0, Math.ceil(ms / 1000));
    const mins = String(Math.floor(totalSeconds / 60)).padStart(2, "0");
    const secs = String(totalSeconds % 60).padStart(2, "0");
    return `${mins}:${secs}`;
  }

  function updateSessionTimerDisplay() {
    if (!sessionTimerEl || !sessionTimerTextEl || !isConsoleUnlocked) return;
    const remainingMs = Math.max(0, sessionExpiresAt - Date.now());
    sessionTimerTextEl.textContent = formatCountdown(remainingMs);
    sessionTimerEl.classList.toggle("is-warning", remainingMs <= 30000);
  }

  function stopSessionMonitor() {
    if (sessionTicker) {
      clearInterval(sessionTicker);
      sessionTicker = null;
    }
    sessionExpiresAt = 0;
    if (sessionTimerEl) {
      sessionTimerEl.hidden = true;
      sessionTimerEl.classList.remove("is-warning");
    }
  }

  function clearSensitiveState() {
    isConsoleUnlocked = false;
    vaultKeyRaw = "";
    allRequests = [];
    keyVisible = false;
    renderVaultKey();
    if (requestsContainer) requestsContainer.replaceChildren();
    if (adminEventSource) {
      adminEventSource.close();
      adminEventSource = null;
    }
    if (unsubscribeList) {
      unsubscribeList();
      unsubscribeList = null;
    }
    stopSessionMonitor();
    if (liveDot) liveDot.hidden = true;
    if (logoutBtn) logoutBtn.hidden = true;
  }

  function renderLockedView(noticeMsg = "") {
    clearSensitiveState();
    hideAllSections();
    if (modeDriver === "firebase") {
      if (firebasePanel) firebasePanel.hidden = false;
      showMessage(firebaseAuthError, noticeMsg);
    } else {
      if (loginPanel) loginPanel.hidden = false;
      showMessage(loginError, "");
      showMessage(loginNotice, noticeMsg);
    }
  }

  async function lockAdminSession({ logoutServer = false, notice = "" } = {}) {
    const currentDriver = modeDriver;
    renderLockedView(notice);
    if (currentDriver === "local" && logoutServer) {
      try {
        await fetch(`${apiBase}/admin/logout`, { method: "POST", credentials: "same-origin" });
      } catch {
        // Best-effort server logout
      }
    } else if (currentDriver === "firebase") {
      try {
        sessionStorage.removeItem(FB_CONSOLE_LOCK_KEY);
      } catch {}
      if (logoutServer && firebaseCtx) {
        try {
          await firebaseCtx.authMod.signOut(firebaseCtx.auth);
        } catch {}
      }
    }
  }

  function startSessionMonitor(expiresAt, timeoutMs) {
    stopSessionMonitor();
    adminTimeoutMs = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_IDLE_TIMEOUT_MS;
    const now = Date.now();
    sessionExpiresAt = expiresAt && Number(expiresAt) > now ? Number(expiresAt) : now + adminTimeoutMs;
    lastLocalActivityAt = now;
    lastServerTouchAt = now;
    if (sessionTimerEl) sessionTimerEl.hidden = false;
    updateSessionTimerDisplay();

    sessionTicker = setInterval(() => {
      if (!isConsoleUnlocked) {
        stopSessionMonitor();
        return;
      }
      updateSessionTimerDisplay();
      if (Date.now() >= sessionExpiresAt) {
        lockAdminSession({
          logoutServer: true,
          notice: "Session timed out after 2 minutes of inactivity. Please enter your passcode again.",
        });
      }
    }, 1000);
  }

  async function touchLocalSession() {
    try {
      const resp = await fetch(`${apiBase}/admin/touch`, {
        method: "POST",
        credentials: "same-origin",
      });
      if (resp.status === 401) {
        const data = await resp.json().catch(() => ({}));
        await lockAdminSession({
          logoutServer: false,
          notice: data.error || "Session expired. Please enter your passcode again.",
        });
        return;
      }
      if (resp.ok) {
        const data = await resp.json();
        if (data.expiresAt && isConsoleUnlocked) {
          sessionExpiresAt = Number(data.expiresAt);
          updateSessionTimerDisplay();
        }
      }
    } catch {
      // Ignore transient network errors during activity heartbeat
    }
  }

  function recordUserActivity() {
    if (!isConsoleUnlocked) return;
    const now = Date.now();
    if (now - lastLocalActivityAt < 1000) return;
    lastLocalActivityAt = now;
    sessionExpiresAt = now + adminTimeoutMs;
    updateSessionTimerDisplay();
    if (modeDriver === "local" && now - lastServerTouchAt >= 15000) {
      lastServerTouchAt = now;
      touchLocalSession();
    }
  }

  function sendLockBeacon() {
    const lockUrl = `${apiBase}/admin/lock`;
    try {
      if (typeof navigator.sendBeacon === "function" && navigator.sendBeacon(lockUrl)) {
        return;
      }
    } catch {}
    try {
      fetch(lockUrl, { method: "POST", keepalive: true, credentials: "same-origin" });
    } catch {}
  }

  function handleLeavePage() {
    if (!isConsoleUnlocked) return;
    const driver = modeDriver;
    renderLockedView("Admin Console locked on navigation. Please enter your passcode again.");
    if (driver === "local") {
      sendLockBeacon();
    } else if (driver === "firebase") {
      try {
        sessionStorage.removeItem(FB_CONSOLE_LOCK_KEY);
      } catch {}
    }
  }

  function maskVaultKey(key) {
    if (!key) return "Unavailable";
    return keyVisible ? key : "•".repeat(Math.max(24, key.length));
  }

  function renderVaultKey() {
    if (!vaultKeyPreview) return;
    vaultKeyPreview.textContent = maskVaultKey(vaultKeyRaw);
    if (toggleKeyBtn) {
      toggleKeyBtn.textContent = keyVisible ? "Hide Key" : "Reveal Key";
    }
  }

  function updateStats(list) {
    const total = list.length;
    const pending = list.filter((r) => r.status === "pending").length;
    const approved = list.filter((r) => r.status === "approved").length;
    const blocked = list.filter((r) => r.status === "rejected" || r.status === "revoked").length;
    if (statTotal) statTotal.textContent = String(total);
    if (statPending) statPending.textContent = String(pending);
    if (statApproved) statApproved.textContent = String(approved);
    if (statBlocked) statBlocked.textContent = String(blocked);
  }

  function renderRequests() {
    if (!requestsContainer) return;
    updateStats(allRequests);

    const query = String(searchInput?.value || "").trim().toLowerCase();
    const filtered = allRequests.filter((item) => {
      if (activeFilter !== "all" && item.status !== activeFilter) return false;
      if (!query) return true;
      const haystack = `${item.name || ""} ${item.email || ""} ${item.purpose || ""} ${item.reason || ""} ${item.id || ""}`.toLowerCase();
      return haystack.includes(query);
    });

    requestsContainer.replaceChildren();

    if (filtered.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-requests";
      const icon = document.createElement("i");
      icon.className = "bi bi-inbox fs-2 d-block mb-2";
      const text = document.createElement("p");
      text.className = "mb-0";
      text.textContent = allRequests.length === 0
        ? "No access requests yet. When someone visits the portfolio and clicks 'Request to View', their request will appear here live."
        : "No requests match the selected filter or search.";
      empty.append(icon, text);
      requestsContainer.appendChild(empty);
      return;
    }

    for (const item of filtered) {
      const card = document.createElement("article");
      card.className = "request-card";

      // Top row
      const top = document.createElement("div");
      top.className = "request-card-top";

      const identity = document.createElement("div");
      identity.className = "request-identity";
      const h3 = document.createElement("h3");
      h3.textContent = item.name || "Unknown Visitor";
      const subline = document.createElement("div");
      subline.className = "request-subline";

      const metaItems = [
        item.email || "No email",
        item.purpose || "Portfolio View",
        item.id || "",
      ];
      if (item.createdAt) {
        const dt = new Date(item.createdAt);
        if (!Number.isNaN(dt.getTime())) metaItems.push(dt.toLocaleString());
      }

      for (const piece of metaItems) {
        if (!piece) continue;
        const span = document.createElement("span");
        span.textContent = piece;
        subline.appendChild(span);
      }
      identity.append(h3, subline);

      const badge = document.createElement("span");
      badge.className = `status-badge ${item.status || "pending"}`;
      badge.textContent = item.status || "pending";

      top.append(identity, badge);

      // Reason box
      const reasonBox = document.createElement("div");
      reasonBox.className = "request-reason-box";
      const reasonLabel = document.createElement("strong");
      reasonLabel.textContent = "Reason: ";
      const reasonText = document.createElement("span");
      reasonText.textContent = item.reason || "—";
      reasonBox.append(reasonLabel, reasonText);

      // Actions row
      const actionsRow = document.createElement("div");
      actionsRow.className = "request-card-actions";

      const noteInput = document.createElement("input");
      noteInput.type = "text";
      noteInput.className = "request-note-input";
      noteInput.placeholder = "Optional note for visitor (shown if approved/declined)...";
      noteInput.maxLength = 240;
      noteInput.value = item.adminNote || "";

      const btnGroup = document.createElement("div");
      btnGroup.className = "request-btn-group";

      if (item.status !== "approved") {
        const approveBtn = document.createElement("button");
        approveBtn.type = "button";
        approveBtn.className = "admin-btn approve sm";
        approveBtn.innerHTML = '<i class="bi bi-check2-circle"></i> Approve';
        approveBtn.addEventListener("click", () => handleDecision(item.id, "approved", noteInput.value, approveBtn));
        btnGroup.appendChild(approveBtn);
      }

      if (item.status === "approved") {
        const revokeBtn = document.createElement("button");
        revokeBtn.type = "button";
        revokeBtn.className = "admin-btn revoke sm";
        revokeBtn.innerHTML = '<i class="bi bi-slash-circle"></i> Revoke Access';
        revokeBtn.addEventListener("click", () => handleDecision(item.id, "revoked", noteInput.value, revokeBtn));
        btnGroup.appendChild(revokeBtn);
      } else if (item.status !== "rejected") {
        const rejectBtn = document.createElement("button");
        rejectBtn.type = "button";
        rejectBtn.className = "admin-btn reject sm";
        rejectBtn.innerHTML = '<i class="bi bi-x-circle"></i> Reject';
        rejectBtn.addEventListener("click", () => handleDecision(item.id, "rejected", noteInput.value, rejectBtn));
        btnGroup.appendChild(rejectBtn);
      }

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "admin-btn danger-ghost sm";
      deleteBtn.innerHTML = '<i class="bi bi-trash"></i> Delete';
      deleteBtn.addEventListener("click", () => handleDelete(item.id, deleteBtn));
      btnGroup.appendChild(deleteBtn);

      actionsRow.append(noteInput, btnGroup);
      card.append(top, reasonBox, actionsRow);
      requestsContainer.appendChild(card);
    }
  }

  async function localAdminRequest(endpoint, options = {}) {
    const resp = await fetch(`${apiBase}${endpoint}`, {
      cache: "no-store",
      credentials: "same-origin",
      ...options,
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401) {
      await lockAdminSession({
        logoutServer: false,
        notice: data.error || "Session expired or locked. Please enter your passcode again.",
      });
      const authErr = new Error(data.error || "Admin authentication required.");
      authErr.isAuthError = true;
      throw authErr;
    }
    if (!resp.ok) {
      throw new Error(data.error || "Request failed.");
    }
    if (data.expiresAt && isConsoleUnlocked) {
      sessionExpiresAt = Number(data.expiresAt);
      updateSessionTimerDisplay();
    }
    return data;
  }

  async function handleDecision(id, status, adminNote, btnEl) {
    if (btnEl) btnEl.disabled = true;
    try {
      if (modeDriver === "local") {
        await localAdminRequest("/admin/decision", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id, status, adminNote }),
        });
        await loadLocalRequests();
      } else if (modeDriver === "firebase" && firebaseCtx) {
        const { db, fsMod } = firebaseCtx;
        await fsMod.updateDoc(fsMod.doc(db, "access_requests", id), {
          status,
          adminNote: String(adminNote || "").trim().slice(0, 240),
          updatedAt: new Date().toISOString(),
        });
      }
    } catch (err) {
      if (!err.isAuthError) {
        alert(err.message || "Failed to update request.");
      }
    } finally {
      if (btnEl) btnEl.disabled = false;
    }
  }

  async function handleDelete(id, btnEl) {
    if (btnEl) btnEl.disabled = true;
    try {
      if (modeDriver === "local") {
        await localAdminRequest(`/admin/requests?id=${encodeURIComponent(id)}`, {
          method: "DELETE",
        });
        await loadLocalRequests();
      } else if (modeDriver === "firebase" && firebaseCtx) {
        const { db, fsMod } = firebaseCtx;
        await fsMod.deleteDoc(fsMod.doc(db, "access_requests", id));
      }
    } catch (err) {
      if (!err.isAuthError) {
        alert(err.message || "Failed to delete request.");
      }
    } finally {
      if (btnEl) btnEl.disabled = false;
    }
  }

  // ---------------- Local Admin Driver ----------------

  async function loadLocalRequests() {
    try {
      const data = await localAdminRequest("/admin/requests");
      allRequests = Array.isArray(data.requests) ? data.requests : [];
      renderRequests();
    } catch (err) {
      if (!err.isAuthError) {
        // Ignore transient fetch errors
      }
    }
  }

  function startLocalAdminEvents() {
    if (adminEventSource) {
      adminEventSource.close();
      adminEventSource = null;
    }
    try {
      adminEventSource = new EventSource(`${apiBase}/admin/events`);
      adminEventSource.addEventListener("requests", () => {
        loadLocalRequests();
      });
      adminEventSource.addEventListener("session-expired", () => {
        lockAdminSession({
          logoutServer: false,
          notice: "Session timed out after 2 minutes of inactivity. Please enter your passcode again.",
        });
      });
      if (liveDot) liveDot.hidden = false;
    } catch {
      if (liveDot) liveDot.hidden = true;
    }
  }

  async function showLocalState(state) {
    hideAllSections();
    if (!state.configured) {
      clearSensitiveState();
      if (setupPanel) setupPanel.hidden = false;
      return;
    }
    if (!state.authenticated) {
      const notice =
        pendingLoginNotice ||
        (state.consoleLocked
          ? "Admin Console is locked. Enter your passcode to continue (Portfolio stays open until session timeout)."
          : "");
      pendingLoginNotice = "";
      renderLockedView(notice);
      return;
    }

    pendingLoginNotice = "";
    isConsoleUnlocked = true;
    vaultKeyRaw = state.vaultKey || "";
    renderVaultKey();
    showMessage(loginNotice, "");
    showMessage(loginError, "");
    if (logoutBtn) logoutBtn.hidden = false;
    if (localPasscodeCard) localPasscodeCard.hidden = false;
    if (dashboard) dashboard.hidden = false;
    startSessionMonitor(state.expiresAt, state.timeoutMs);
    await loadLocalRequests();
    startLocalAdminEvents();
  }

  async function checkLocalAdmin() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2200);
    try {
      const resp = await fetch(`${apiBase}/admin/state`, {
        cache: "no-store",
        credentials: "same-origin",
        signal: controller.signal,
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data && data.mode === "local" ? data : null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------- Firebase Admin Driver ----------------

  async function initFirebaseAdmin() {
    const fbCfg = cfg.firebaseConfig || {};
    const version = "11.0.2";
    const [appMod, authMod, fsMod] = await Promise.all([
      import(`https://www.gstatic.com/firebasejs/${version}/firebase-app.js`),
      import(`https://www.gstatic.com/firebasejs/${version}/firebase-auth.js`),
      import(`https://www.gstatic.com/firebasejs/${version}/firebase-firestore.js`),
    ]);

    const app = appMod.getApps().length ? appMod.getApp() : appMod.initializeApp(fbCfg);
    const auth = authMod.getAuth(app);
    const db = fsMod.getFirestore(app);
    firebaseCtx = { auth, db, authMod, fsMod };

    if (firebaseAdminEmailLabel) {
      firebaseAdminEmailLabel.textContent = cfg.adminEmail || "Owner Email";
    }

    authMod.onAuthStateChanged(auth, async (user) => {
      if (unsubscribeList) {
        unsubscribeList();
        unsubscribeList = null;
      }

      const isOwner =
        Boolean(user) &&
        !user.isAnonymous &&
        user.email === cfg.adminEmail &&
        user.emailVerified;

      let fbConsoleUnlocked = false;
      try {
        fbConsoleUnlocked = sessionStorage.getItem(FB_CONSOLE_LOCK_KEY) === "1";
      } catch {}

      hideAllSections();
      if (!isOwner || !fbConsoleUnlocked) {
        clearSensitiveState();
        if (firebasePanel) firebasePanel.hidden = false;
        if (user && !user.isAnonymous && user.email !== cfg.adminEmail) {
          showMessage(
            firebaseAuthError,
            `Signed in as ${user.email}, which does not match authorized owner email ${cfg.adminEmail}.`
          );
        } else if (isOwner && !fbConsoleUnlocked) {
          showMessage(firebaseAuthError, "Admin Console locked. Re-verify with Google to enter Console.");
        }
        return;
      }

      isConsoleUnlocked = true;
      if (logoutBtn) logoutBtn.hidden = false;
      if (localPasscodeCard) localPasscodeCard.hidden = true;
      if (dashboard) dashboard.hidden = false;
      if (liveDot) liveDot.hidden = false;
      startSessionMonitor(Date.now() + DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS);

      try {
        const keySnap = await fsMod.getDoc(fsMod.doc(db, "vault_secrets", "portfolio_key"));
        vaultKeyRaw = keySnap.exists() ? keySnap.data().keyBase64 || "" : "";
        renderVaultKey();
      } catch {
        vaultKeyRaw = "";
        renderVaultKey();
      }

      const q = fsMod.query(fsMod.collection(db, "access_requests"), fsMod.orderBy("createdAt", "desc"));
      unsubscribeList = fsMod.onSnapshot(q, (snap) => {
        allRequests = snap.docs.map((docSnap) => ({
          ...docSnap.data(),
          id: docSnap.id,
        }));
        renderRequests();
      });
    });
  }

  // ---------------- Event Bindings ----------------

  if (setupForm) {
    setupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      showMessage(setupError, "");
      const p1 = String(document.getElementById("setupPasscode")?.value || "");
      const p2 = String(document.getElementById("setupPasscodeConfirm")?.value || "");
      if (p1.length < 6) {
        showMessage(setupError, "Passcode must be at least 6 characters.");
        return;
      }
      if (p1 !== p2) {
        showMessage(setupError, "Passcodes do not match.");
        return;
      }
      try {
        const resp = await fetch(`${apiBase}/admin/setup`, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ passcode: p1 }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || "Setup failed.");
        setupForm.reset();
        await showLocalState(data);
      } catch (err) {
        showMessage(setupError, err.message);
      }
    });
  }

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      showMessage(loginError, "");
      showMessage(loginNotice, "");
      const passcode = String(document.getElementById("loginPasscode")?.value || "");
      try {
        const resp = await fetch(`${apiBase}/admin/login`, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ passcode }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || "Sign in failed.");
        loginForm.reset();
        await showLocalState({
          configured: true,
          authenticated: true,
          expiresAt: data.expiresAt,
          timeoutMs: data.timeoutMs,
          vaultKey: data.vaultKey,
        });
      } catch (err) {
        showMessage(loginError, err.message);
      }
    });
  }

  if (firebaseGoogleBtn) {
    firebaseGoogleBtn.addEventListener("click", async () => {
      if (!firebaseCtx) return;
      showMessage(firebaseAuthError, "");
      try {
        try {
          sessionStorage.setItem(FB_CONSOLE_LOCK_KEY, "1");
        } catch {}
        const provider = new firebaseCtx.authMod.GoogleAuthProvider();
        provider.setCustomParameters({ prompt: "select_account" });
        await firebaseCtx.authMod.signInWithPopup(firebaseCtx.auth, provider);
      } catch (err) {
        try {
          sessionStorage.removeItem(FB_CONSOLE_LOCK_KEY);
        } catch {}
        showMessage(firebaseAuthError, err.message || "Google sign-in failed.");
      }
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      await lockAdminSession({
        logoutServer: true,
        notice: "Signed out of Admin Console and locked Portfolio.",
      });
    });
  }

  if (changePasscodeForm) {
    changePasscodeForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (passcodeMsg) {
        passcodeMsg.hidden = true;
        passcodeMsg.className = "admin-feedback";
      }
      const currentPasscode = String(document.getElementById("currentPasscode")?.value || "");
      const newPasscode = String(document.getElementById("newPasscode")?.value || "");
      try {
        await localAdminRequest("/admin/change-passcode", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ currentPasscode, newPasscode }),
        });
        changePasscodeForm.reset();
        if (passcodeMsg) {
          passcodeMsg.textContent = "Admin passcode updated cleanly.";
          passcodeMsg.classList.add("ok");
          passcodeMsg.hidden = false;
        }
      } catch (err) {
        if (!err.isAuthError && passcodeMsg) {
          passcodeMsg.textContent = err.message;
          passcodeMsg.className = "admin-error";
          passcodeMsg.hidden = false;
        }
      }
    });
  }

  filterTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      filterTabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      activeFilter = tab.getAttribute("data-filter") || "all";
      renderRequests();
    });
  });

  if (searchInput) {
    searchInput.addEventListener("input", renderRequests);
  }

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      if (modeDriver === "local") loadLocalRequests();
    });
  }

  if (toggleKeyBtn) {
    toggleKeyBtn.addEventListener("click", () => {
      keyVisible = !keyVisible;
      renderVaultKey();
    });
  }

  if (copyKeyBtn) {
    copyKeyBtn.addEventListener("click", async () => {
      if (!vaultKeyRaw) return;
      try {
        await navigator.clipboard.writeText(vaultKeyRaw);
        copyKeyBtn.textContent = "Copied!";
        setTimeout(() => {
          copyKeyBtn.textContent = "Copy Key";
        }, 1800);
      } catch {
        keyVisible = true;
        renderVaultKey();
      }
    });
  }

  ["pointerdown", "keydown", "scroll", "touchstart", "mousemove"].forEach((evt) => {
    window.addEventListener(evt, recordUserActivity, { passive: true });
  });
  window.addEventListener("pagehide", handleLeavePage);
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
      const wasUnlocked = isConsoleUnlocked;
      clearSensitiveState();
      if (wasUnlocked && !pendingLoginNotice) {
        pendingLoginNotice = "Admin Console locked on navigation. Please enter your passcode again.";
      }
      boot({ forceLock: true });
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && isConsoleUnlocked && Date.now() >= sessionExpiresAt) {
      lockAdminSession({
        logoutServer: true,
        notice: "Session timed out after 2 minutes of inactivity. Please enter your passcode again.",
      });
    }
  });

  async function boot(options = {}) {
    const navType = performance.getEntriesByType?.("navigation")?.[0]?.type || "";
    const shouldForceLock = Boolean(options.forceLock) || navType === "back_forward";
    if (shouldForceLock) {
      try {
        sessionStorage.removeItem(FB_CONSOLE_LOCK_KEY);
      } catch {}
      try {
        await fetch(`${apiBase}/admin/lock`, { method: "POST", credentials: "same-origin" });
      } catch {}
    }

    const localState = await checkLocalAdmin();
    if (localState) {
      modeDriver = "local";
      if (modePill) modePill.textContent = "Local Gate Server";
      await showLocalState(localState);
      return;
    }

    if (cfg.firebaseConfig && cfg.firebaseConfig.apiKey) {
      modeDriver = "firebase";
      if (modePill) modePill.textContent = "Firebase Cloud Mode";
      await initFirebaseAdmin();
      return;
    }

    hideAllSections();
    if (modePill) modePill.textContent = "Setup Required";
    if (unconfiguredPanel) unconfiguredPanel.hidden = false;
  }

  boot();
})();
