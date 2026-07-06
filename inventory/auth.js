/* Auth gate — talks to the Cloudflare Worker API (/api/auth/*).
   Loaded before app.js. Shows a login overlay until the user has a valid token. */

const API_BASE = "/api";
const TOKEN_KEY = "dr_token";
const EMAIL_KEY = "dr_email";

/* ---------- Token storage ---------- */
function getToken() { return localStorage.getItem(TOKEN_KEY); }
function setSession(token, email) {
  localStorage.setItem(TOKEN_KEY, token);
  if (email) localStorage.setItem(EMAIL_KEY, email);
}
function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(EMAIL_KEY);
}

/* Adds the Authorization header to any fetch the app makes to the API.
   app.js can call authFetch(url, opts) instead of fetch() once it talks to D1. */
function authFetch(url, opts = {}) {
  const token = getToken();
  const headers = { ...(opts.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return fetch(url, { ...opts, headers });
}

/* ---------- Overlay control ---------- */
function showLogin() { document.getElementById("authOverlay").style.display = "flex"; }
function hideLogin() { document.getElementById("authOverlay").style.display = "none"; }
function setAuthError(msg) {
  const el = document.getElementById("authError");
  el.textContent = msg || "";
  el.style.display = msg ? "block" : "none";
}

/* ---------- API calls ---------- */
// Both return { ok, status, data }. They throw only on network failure.
async function apiAuth(endpoint, body) {
  const res = await fetch(`${API_BASE}/auth/${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}
const apiLogin = (email, password) => apiAuth("login", { email, password });
const apiRegister = (email, password) => apiAuth("register", { email, password });

/* ---------- Mode: login <-> register ---------- */
let mode = "login"; // "login" | "register"

function setMode(next) {
  mode = next;
  const isLogin = mode === "login";
  document.getElementById("authTitle").textContent = isLogin ? "Prihlásenie" : "Registrácia";
  document.getElementById("authSubmit").textContent = isLogin ? "Prihlásiť sa" : "Zaregistrovať sa";
  document.getElementById("authTogglePrompt").textContent = isLogin ? "Nemáte účet?" : "Už máte účet?";
  document.getElementById("authToggle").textContent = isLogin ? "Zaregistrujte sa" : "Prihláste sa";
  document.getElementById("auth-password").setAttribute(
    "autocomplete", isLogin ? "current-password" : "new-password"
  );
  setAuthError("");
}

/* ---------- Submit handler ---------- */
async function handleSubmit(event) {
  event.preventDefault();
  const email = document.getElementById("auth-email").value.trim();
  const password = document.getElementById("auth-password").value;
  const submitBtn = document.getElementById("authSubmit");

  setAuthError("");
  if (!email || !password) {
    setAuthError("Zadajte email aj heslo.");
    return;
  }
  if (mode === "register" && password.length < 6) {
    setAuthError("Heslo musí mať aspoň 6 znakov.");
    return;
  }

  submitBtn.disabled = true;
  const labelWas = submitBtn.textContent;
  submitBtn.textContent = "…";
  try {
    const result = mode === "login"
      ? await apiLogin(email, password)
      : await apiRegister(email, password);
    if (result.ok && result.data.token) {
      setSession(result.data.token, result.data.email);
      hideLogin();
    } else {
      setAuthError(result.data.error || "Niečo sa pokazilo. Skúste znova.");
    }
  } catch (e) {
    setAuthError("Nepodarilo sa spojiť so serverom.");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = labelWas;
  }
}

/* ---------- Wiring ---------- */
document.getElementById("authForm").addEventListener("submit", handleSubmit);
document.getElementById("authToggle").addEventListener("click", (e) => {
  e.preventDefault();
  setMode(mode === "login" ? "register" : "login");
});

// V lokálnom náhľade (preview) preskočíme prihlásenie, aby sa dal web pozrieť.
const IS_PREVIEW = ["localhost", "127.0.0.1", ""].includes(location.hostname)
  || location.hostname.endsWith(".local");

// On load: if we already have a token (or sme v preview), skip the auth screen.
if (getToken() || IS_PREVIEW) {
  hideLogin();
} else {
  showLogin();
}
