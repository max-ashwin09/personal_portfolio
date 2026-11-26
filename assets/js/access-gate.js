/**
 * VCRYPT Portfolio Access Gate Client
 * Enforces default-deny blurred state until owner approves access, then decrypts
 * the AES-256-GCM portfolio payload in browser memory and boots interactive UI.
 */

(function () {
  "use strict";

  const cfg = window.VCRYPT_GATE_CONFIG || {};
  const apiBase = cfg.localApiBase || "/api";
  const pageKey = document.body.getAttribute("data-gate-page") || "index.html";
  const params = new URLSearchParams(window.location.search);
  const visitorPreview = params.get("preview") === "locked";
  const lockedTitle = document.title;

  const unlockedRoot = document.getElementById("vcrypt-unlocked-root");
  const gateStage = document.getElementById("vcrypt-gate-stage");
  const ownerBar = document.getElementById("vcrypt-owner-bar");
  const previewLockBtn = document.getElementById("vcryptPreviewLockBtn");

  const statusBadge = document.getElementById("vcryptStatusBadge");
  const loadingBox = document.getElementById("vcryptLoadingState");
  const requestForm = document.getElementById("vcryptRequestForm");
  const formError = document.getElementById("vcryptFormError");
  const submitBtn = document.getElementById("vcryptSubmitBtn");

  const statusPanel = document.getElementById("vcryptStatusPanel");
  const panelIcon = document.getElementById("vcryptPanelIcon");
  const panelHeading = document.getElementById("vcryptPanelHeading");
  const panelMessage = document.getElementById("vcryptPanelMessage");
  const requestMeta = document.getElementById("vcryptRequestMeta");
  const checkBtn = document.getElementById("vcryptCheckBtn");
  const newRequestBtn = document.getElementById("vcryptNewRequestBtn");

  let modeDriver = null; // 'local' | 'firebase' | 'unconfigured'
  let isCurrentlyUnlocked = false;
  let forceNewRequestFlag = false;
  let eventSource = null;
  let pollTimer = null;
  let firebaseCtx = null;
  let unsubscribeSnapshot = null;
  let ownerExpiryTimer = null;
  let ownerExpiresAtMs = 0;

  function stopOwnerCountdown() {
    if (ownerExpiryTimer) {
      clearInterval(ownerExpiryTimer);
      ownerExpiryTimer = null;
    }
    ownerExpiresAtMs = 0;
  }

  function formatRemaining(ms) {
    const totalSecs = Math.max(0, Math.ceil(ms / 1000));
    const mins = String(Math.floor(totalSecs / 60)).padStart(2, "0");
    const secs = String(totalSecs % 60).padStart(2, "0");
    return `${mins}:${secs}`;
  }

  function updateOwnerBarCountdown() {
    if (!ownerBar) return;
    const labelSpan = ownerBar.querySelector("span");
    if (!labelSpan) return;
    labelSpan.replaceChildren();
    const icon = document.createElement("i");
    icon.className = "bi bi-shield-check";
    const text = document.createTextNode(
      ownerExpiresAtMs > 0
        ? ` Unlocked via Owner Session (${formatRemaining(ownerExpiresAtMs - Date.now())})`
        : " Unlocked via Owner Session"
    );
    labelSpan.append(icon, text);
  }

  function startOwnerCountdown(expiresAt) {
    stopOwnerCountdown();
    if (!expiresAt || Number(expiresAt) <= Date.now()) {
      updateOwnerBarCountdown();
      return;
    }
    ownerExpiresAtMs = Number(expiresAt);
    updateOwnerBarCountdown();
    ownerExpiryTimer = setInterval(async () => {
      if (Date.now() >= ownerExpiresAtMs) {
        stopOwnerCountdown();
        if (modeDriver === "local") {
          try {
            const latest = await fetchLocalStatus();
            await handleGateStateUpdate(latest);
          } catch {
            applyLockedState({ status: "none" });
          }
        }
        return;
      }
      updateOwnerBarCountdown();
    }, 1000);
  }

  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function decryptVaultPage(vaultKeyBase64, targetPage) {
    const resp = await fetch("assets/data/vault.enc.json", { cache: "no-store" });
    if (!resp.ok) {
      throw new Error("Encrypted portfolio bundle could not be loaded.");
    }
    const bundle = await resp.json();
    const keyBytes = base64ToBytes(vaultKeyBase64);
    const ivBytes = base64ToBytes(bundle.iv);
    const cipherBytes = base64ToBytes(bundle.data);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const plainBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      cryptoKey,
      cipherBytes
    );

    const decoded = new TextDecoder().decode(plainBuffer);
    const payload = JSON.parse(decoded);
    const pageData = payload.pages && payload.pages[targetPage];
    if (!pageData) {
      throw new Error(`No page entry found for ${targetPage}`);
    }
    return pageData;
  }

  function setBadge(text, iconClass, variantClass) {
    if (!statusBadge) return;
    statusBadge.className = "vcrypt-badge-pill" + (variantClass ? ` ${variantClass}` : "");
    statusBadge.replaceChildren();
    const icon = document.createElement("i");
    icon.className = `bi ${iconClass}`;
    const span = document.createElement("span");
    span.textContent = text;
    statusBadge.append(icon, span);
  }

  function renderMetaLines(req) {
    if (!requestMeta) return;
    requestMeta.replaceChildren();
    if (!req) return;

    const rows = [
      ["Request ID", req.id || "—"],
      ["Name", req.name || "—"],
      ["Email", req.email || "—"],
      ["Purpose", req.purpose || "—"],
    ];
    if (req.adminNote) {
      rows.push(["Owner Note", req.adminNote]);
    }
    if (req.updatedAt || req.createdAt) {
      const dt = new Date(req.updatedAt || req.createdAt);
      if (!Number.isNaN(dt.getTime())) {
        rows.push(["Updated", dt.toLocaleString()]);
      }
    }

    for (const [label, value] of rows) {
      const line = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = `${label}: `;
      const span = document.createElement("span");
      span.textContent = value;
      line.append(strong, span);
      requestMeta.appendChild(line);
    }
  }

  function showFormError(msg) {
    if (!formError) return;
    if (!msg) {
      formError.hidden = true;
      formError.textContent = "";
      return;
    }
    formError.textContent = msg;
    formError.hidden = false;
  }

  function showFormState(prefillRequest) {
    if (loadingBox) loadingBox.hidden = true;
    if (statusPanel) statusPanel.hidden = true;
    if (requestForm) {
      requestForm.hidden = false;
      if (prefillRequest) {
        const nameEl = document.getElementById("reqName");
        const emailEl = document.getElementById("reqEmail");
        const purposeEl = document.getElementById("reqPurpose");
        const reasonEl = document.getElementById("reqReason");
        if (nameEl && !nameEl.value) nameEl.value = prefillRequest.name || "";
        if (emailEl && !emailEl.value) emailEl.value = prefillRequest.email || "";
        if (purposeEl && prefillRequest.purpose) purposeEl.value = prefillRequest.purpose;
        if (reasonEl && !reasonEl.value) reasonEl.value = prefillRequest.reason || "";
      }
    }
    setBadge("Approval Required", "bi-shield-lock-fill", "");
  }

  function showStatusState(payload) {
    if (loadingBox) loadingBox.hidden = true;
    if (requestForm) requestForm.hidden = true;
    if (statusPanel) statusPanel.hidden = false;

    const status = payload.status;
    renderMetaLines(payload.request);

    if (status === "pending") {
      setBadge("Pending Approval", "bi-hourglass-split", "is-pending");
      if (panelIcon) {
        panelIcon.className = "vcrypt-status-icon";
        panelIcon.innerHTML = '<i class="bi bi-hourglass-split"></i>';
      }
      if (panelHeading) panelHeading.textContent = "Waiting for Owner Approval";
      if (panelMessage) {
        panelMessage.textContent =
          "Your request has been logged. Keep this tab open — as soon as Vivek approves your request in the Admin Console, this page will unlock automatically.";
      }
      if (checkBtn) checkBtn.hidden = false;
      if (newRequestBtn) newRequestBtn.hidden = false;
    } else if (status === "rejected" || status === "revoked") {
      const isRevoked = status === "revoked";
      setBadge(isRevoked ? "Access Revoked" : "Request Declined", "bi-shield-x", "is-rejected");
      if (panelIcon) {
        panelIcon.className = "vcrypt-status-icon is-rejected";
        panelIcon.innerHTML = '<i class="bi bi-shield-exclamation"></i>';
      }
      if (panelHeading) {
        panelHeading.textContent = isRevoked
          ? "Access Has Been Revoked"
          : "Access Request Not Approved";
      }
      if (panelMessage) {
        panelMessage.textContent = isRevoked
          ? "The owner has revoked access for this session. Submit a new request if you still need access."
          : "The owner declined this access request. You can submit an updated request with additional context if needed.";
      }
      if (checkBtn) checkBtn.hidden = false;
      if (newRequestBtn) newRequestBtn.hidden = false;
    } else if (status === "unconfigured") {
      setBadge("Setup Required", "bi-gear-fill", "is-rejected");
      if (panelIcon) {
        panelIcon.className = "vcrypt-status-icon is-rejected";
        panelIcon.innerHTML = '<i class="bi bi-cloud-slash"></i>';
      }
      if (panelHeading) panelHeading.textContent = "Approval Backend Not Configured";
      if (panelMessage) {
        panelMessage.textContent =
          "Start the local Gate Server (`node server.mjs`) or configure Firebase in `assets/js/gate-config.js` via Owner Admin Console.";
      }
      if (checkBtn) checkBtn.hidden = false;
      if (newRequestBtn) newRequestBtn.hidden = true;
    }
  }

  async function applyUnlockedState(payload) {
    if (!payload.vaultKey) {
      applyLockedState({
        status: "pending",
        request: payload.request || null,
      });
      return;
    }

    if (isCurrentlyUnlocked) {
      if (ownerBar) {
        const showOwnerBar = Boolean(payload.isAdmin && !visitorPreview);
        ownerBar.hidden = !showOwnerBar;
        if (showOwnerBar) {
          startOwnerCountdown(payload.adminExpiresAt);
        } else {
          stopOwnerCountdown();
        }
      }
      return;
    }

    try {
      const pageData = await decryptVaultPage(payload.vaultKey, pageKey);
      document.title = pageData.title || document.title;
      document.body.className = pageData.bodyClass || "";

      if (unlockedRoot) {
        unlockedRoot.innerHTML = pageData.contentHtml;
        unlockedRoot.hidden = false;
      }
      if (gateStage) {
        gateStage.hidden = true;
      }
      if (ownerBar) {
        const showOwnerBar = Boolean(payload.isAdmin && !visitorPreview);
        ownerBar.hidden = !showOwnerBar;
        if (showOwnerBar) {
          startOwnerCountdown(payload.adminExpiresAt);
        } else {
          stopOwnerCountdown();
        }
      }

      isCurrentlyUnlocked = true;
      if (typeof window.initPortfolioApp === "function") {
        window.initPortfolioApp();
      }
    } catch (err) {
      isCurrentlyUnlocked = false;
      showFormError(err.message || "Failed to decrypt protected content.");
      showStatusState({ status: payload.status || "pending", request: payload.request });
    }
  }

  function applyLockedState(payload) {
    stopOwnerCountdown();
    if (isCurrentlyUnlocked) {
      isCurrentlyUnlocked = false;
      if (unlockedRoot) {
        unlockedRoot.innerHTML = "";
        unlockedRoot.hidden = true;
      }
      document.body.className = "gate-locked-body";
      document.title = lockedTitle;
      window.scrollTo({ top: 0, behavior: "instant" });
    }

    if (ownerBar) ownerBar.hidden = true;
    if (gateStage) gateStage.hidden = false;

    if (!payload || payload.status === "none") {
      showFormState(null);
      return;
    }
    showStatusState(payload);
  }

  async function handleGateStateUpdate(payload) {
    if (!payload) return;
    if (payload.unlocked && payload.vaultKey) {
      await applyUnlockedState(payload);
    } else {
      applyLockedState(payload);
    }
  }

  // ---------------- Local Node Gate Server Driver ----------------

  async function fetchLocalStatus() {
    const suffix = visitorPreview ? "?visitorPreview=1" : "";
    const resp = await fetch(`${apiBase}/gate/status${suffix}`, {
      cache: "no-store",
      credentials: "same-origin",
    });
    if (!resp.ok) {
      throw new Error("Unable to fetch gate status.");
    }
    return resp.json();
  }

  function startLocalLiveUpdates() {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    const suffix = visitorPreview ? "?visitorPreview=1" : "";
    try {
      eventSource = new EventSource(`${apiBase}/gate/events${suffix}`);
      eventSource.addEventListener("status", (event) => {
        try {
          const payload = JSON.parse(event.data);
          handleGateStateUpdate(payload);
        } catch {
          // Ignore malformed event
        }
      });
      eventSource.onerror = () => {
        if (!pollTimer) {
          pollTimer = setInterval(async () => {
            try {
              const latest = await fetchLocalStatus();
              handleGateStateUpdate(latest);
            } catch {
              // Retry silently
            }
          }, 4000);
        }
      };
    } catch {
      pollTimer = setInterval(async () => {
        try {
          const latest = await fetchLocalStatus();
          handleGateStateUpdate(latest);
        } catch {
          // Retry silently
        }
      }, 4000);
    }
  }

  async function detectLocalServer() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2200);
    try {
      const resp = await fetch(`${apiBase}/gate/mode`, {
        cache: "no-store",
        signal: controller.signal,
      });
      if (!resp.ok) return false;
      const data = await resp.json();
      return data && data.mode === "local";
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------- Firebase Cloud Mode Driver ----------------

  async function initFirebaseDriver() {
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

    authMod.onAuthStateChanged(auth, async (user) => {
      if (unsubscribeSnapshot) {
        unsubscribeSnapshot();
        unsubscribeSnapshot = null;
      }

      if (!user) {
        try {
          await authMod.signInAnonymously(auth);
        } catch (err) {
          showStatusState({
            status: "unconfigured",
            request: { id: "AUTH_ERROR", reason: err.message || "Enable Anonymous Auth in Firebase Console." },
          });
        }
        return;
      }

      const isVerifiedOwner =
        !user.isAnonymous &&
        user.email === cfg.adminEmail &&
        user.emailVerified &&
        !visitorPreview;

      if (isVerifiedOwner) {
        try {
          const keySnap = await fsMod.getDoc(fsMod.doc(db, "vault_secrets", "portfolio_key"));
          if (keySnap.exists() && keySnap.data().keyBase64) {
            await applyUnlockedState({
              unlocked: true,
              isAdmin: true,
              status: "owner",
              vaultKey: keySnap.data().keyBase64,
            });
            return;
          }
        } catch {
          // Fall through to visitor flow
        }
      }

      const reqRef = fsMod.doc(db, "access_requests", user.uid);
      unsubscribeSnapshot = fsMod.onSnapshot(
        reqRef,
        async (snap) => {
          if (!snap.exists()) {
            applyLockedState({ status: "none" });
            return;
          }

          const data = snap.data();
          if (data.status === "approved") {
            try {
              const keySnap = await fsMod.getDoc(fsMod.doc(db, "vault_secrets", "portfolio_key"));
              const keyBase64 = keySnap.exists() ? keySnap.data().keyBase64 : null;
              await handleGateStateUpdate({
                status: "approved",
                unlocked: Boolean(keyBase64),
                isAdmin: false,
                request: data,
                vaultKey: keyBase64,
              });
            } catch {
              applyLockedState({ status: "pending", request: data });
            }
          } else {
            applyLockedState({
              status: data.status || "pending",
              request: data,
            });
          }
        },
        (err) => {
          showFormError(err.message || "Unable to read approval status.");
          applyLockedState({ status: "none" });
        }
      );
    });
  }

  async function notifyWeb3Forms(formPayload) {
    if (!cfg.web3formsAccessKey) return;
    try {
      await fetch("https://api.web3forms.com/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          access_key: cfg.web3formsAccessKey,
          subject: `Portfolio Access Request from ${formPayload.name}`,
          from_name: formPayload.name,
          email: formPayload.email,
          message: `Name: ${formPayload.name}\nEmail: ${formPayload.email}\nPurpose: ${formPayload.purpose}\nReason: ${formPayload.reason}\n\nOpen Admin Console to approve or reject.`,
        }),
      });
    } catch {
      // Optional notification best-effort only
    }
  }

  // ---------------- Event Handlers ----------------

  if (requestForm) {
    requestForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      showFormError("");

      const name = String(document.getElementById("reqName")?.value || "").trim();
      const email = String(document.getElementById("reqEmail")?.value || "").trim();
      const purpose = String(document.getElementById("reqPurpose")?.value || "").trim();
      const reason = String(document.getElementById("reqReason")?.value || "").trim();

      if (name.length < 2 || !email || reason.length < 3) {
        showFormError("Please complete all required fields.");
        return;
      }

      if (submitBtn) submitBtn.disabled = true;

      try {
        if (modeDriver === "local") {
          const resp = await fetch(`${apiBase}/gate/request`, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              name,
              email,
              purpose,
              reason,
              forceNew: forceNewRequestFlag,
            }),
          });
          const data = await resp.json();
          if (!resp.ok) {
            throw new Error(data.error || "Could not submit request.");
          }
          forceNewRequestFlag = false;
          notifyWeb3Forms({ name, email, purpose, reason });
          startLocalLiveUpdates();
          await handleGateStateUpdate(data);
        } else if (modeDriver === "firebase" && firebaseCtx) {
          const { auth, db, authMod, fsMod } = firebaseCtx;
          if (forceNewRequestFlag && auth.currentUser) {
            await authMod.signOut(auth);
            await authMod.signInAnonymously(auth);
            forceNewRequestFlag = false;
          }
          const user = auth.currentUser;
          if (!user) throw new Error("Visitor authentication not ready yet.");

          const reqRef = fsMod.doc(db, "access_requests", user.uid);
          const nowIso = new Date().toISOString();
          await fsMod.setDoc(reqRef, {
            id: `REQ-${user.uid.slice(0, 8).toUpperCase()}`,
            uid: user.uid,
            name,
            email,
            purpose,
            reason,
            status: "pending",
            adminNote: "",
            createdAt: nowIso,
            updatedAt: nowIso,
          });
          notifyWeb3Forms({ name, email, purpose, reason });
        } else {
          throw new Error("Approval backend is not active.");
        }
      } catch (err) {
        showFormError(err.message || "Request submission failed.");
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }

  if (checkBtn) {
    checkBtn.addEventListener("click", async () => {
      if (modeDriver === "local") {
        checkBtn.disabled = true;
        try {
          const latest = await fetchLocalStatus();
          await handleGateStateUpdate(latest);
        } catch (err) {
          showFormError(err.message || "Status refresh failed.");
        } finally {
          checkBtn.disabled = false;
        }
      } else if (modeDriver === "firebase" && firebaseCtx && firebaseCtx.auth.currentUser) {
        checkBtn.disabled = true;
        try {
          const { auth, db, fsMod } = firebaseCtx;
          const snap = await fsMod.getDoc(fsMod.doc(db, "access_requests", auth.currentUser.uid));
          if (!snap.exists()) {
            applyLockedState({ status: "none" });
          } else {
            const data = snap.data();
            if (data.status === "approved") {
              const keySnap = await fsMod.getDoc(fsMod.doc(db, "vault_secrets", "portfolio_key"));
              const keyBase64 = keySnap.exists() ? keySnap.data().keyBase64 : null;
              await handleGateStateUpdate({
                status: "approved",
                unlocked: Boolean(keyBase64),
                request: data,
                vaultKey: keyBase64,
              });
            } else {
              applyLockedState({ status: data.status || "pending", request: data });
            }
          }
        } finally {
          checkBtn.disabled = false;
        }
      }
    });
  }

  if (newRequestBtn) {
    newRequestBtn.addEventListener("click", () => {
      forceNewRequestFlag = true;
      showFormError("");
      showFormState(null);
    });
  }

  if (previewLockBtn) {
    previewLockBtn.addEventListener("click", () => {
      const nextUrl = new URL(window.location.href);
      nextUrl.searchParams.set("preview", "locked");
      window.location.href = nextUrl.toString();
    });
  }

  // ---------------- Boot Gate ----------------

  async function bootGate() {
    if (await detectLocalServer()) {
      modeDriver = "local";
      try {
        const initial = await fetchLocalStatus();
        await handleGateStateUpdate(initial);
        startLocalLiveUpdates();
      } catch (err) {
        showFormError(err.message || "Failed to initialize gate.");
        showFormState(null);
      }
      return;
    }

    if (cfg.firebaseConfig && cfg.firebaseConfig.apiKey) {
      modeDriver = "firebase";
      await initFirebaseDriver();
      return;
    }

    modeDriver = "unconfigured";
    applyLockedState({ status: "unconfigured" });
  }

  window.addEventListener("pageshow", (event) => {
    if (event.persisted && modeDriver === "local") {
      fetchLocalStatus().then(handleGateStateUpdate).catch(() => {});
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && modeDriver === "local") {
      fetchLocalStatus().then(handleGateStateUpdate).catch(() => {});
    }
  });

  bootGate();
})();
