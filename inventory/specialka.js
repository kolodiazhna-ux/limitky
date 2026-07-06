/* Špeciálka — tabuľkový pohľad, rovnaký štýl ako hlavný sklad.
   Číta tie isté dáta (localStorage "dr_inventory_v2"). */

const STORAGE_KEY = "dr_inventory_v2";

/* ---------- Helpers ---------- */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function fmtDate(iso) {
  if (!iso) return "";
  const [y, m, d] = iso.split("-");
  return `${+d}.${+m}.${y}`;
}

function qtyClass(q) { return q <= 0 ? "qty-out" : q <= 3 ? "qty-low" : "qty-ok"; }

function statusClass(v) {
  if (v === "Bratislava") return "b-ok";
  if (v === "Partizánske") return "b-blue";
  if (v === "Výroba") return "b-neutral";
  if (v && v.startsWith("Na ceste")) return "b-warn";
  return "b-empty";
}

function kovanieLabel(v) {
  if (v === "Zlaté")      return `<span class="kov-dot kov-gold" title="Zlaté"></span>`;
  if (v === "Strieborné") return `<span class="kov-dot kov-silver" title="Strieborné"></span>`;
  return "";
}

function linkCell(url) {
  return url
    ? `<a class="link-open" href="${esc(url)}" target="_blank" rel="noopener" title="${esc(url)}">↗</a>`
    : `<span style="color:var(--muted)">—</span>`;
}

let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

/* ---------- Data ---------- */
function loadProducts() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch (e) { return []; }
}

// Odstráni diakritiku, aby "Špecialitka" == "specialitka"
function noDiacritics(s) {
  return String(s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase();
}

function isSpecialka(p) {
  // Ak má produkt uloženú kategóriu (nové produkty), rozhoduje ona.
  if (p.category) return p.category === "specialka";
  // Inak (staré dáta) odhadneme: názov obsahuje "ŠPECIALITKA" / "SPECIALITKA",
  //             alebo kód obsahuje "SPE" (napr. EMASPE1),
  //             alebo poznámka/kód obsahuje "SPEC".
  const name = noDiacritics(p.name);
  const code = noDiacritics(p.code);
  const note = noDiacritics(p.note);
  return name.includes("SPECIALITKA") ||
         code.includes("SPE") ||
         note.includes("SPEC");
}

/* ---------- Priečinky (rovnaké ako na hlavnej stránke) ---------- */
const BUCKETS = [
  { v: "", label: "Pripravuje sa" },
  { v: "mail", label: "Odoslané na mail" },
  { v: "soldout", label: "Hotové" },
];
let currentBucket = "";

function renderTabs() {
  const all = loadProducts().filter(isSpecialka);
  document.getElementById("viewTabs").innerHTML = BUCKETS.map((b) => {
    const cnt = all.filter((p) => (p.bucket || "") === b.v).length;
    return `<button class="view-tab ${b.v === currentBucket ? "active" : ""}" data-bucket="${b.v}">
      ${b.label}<span class="cnt">${cnt}</span></button>`;
  }).join("");
  document.querySelectorAll("#viewTabs [data-bucket]").forEach((t) => {
    t.addEventListener("click", () => { currentBucket = t.dataset.bucket; render(); });
  });
}

// Presunie produkt do iného priečinka a uloží.
function moveToBucket(id, bucket) {
  const rows = loadProducts();
  const row = rows.find((r) => r.id === id);
  if (!row) return;
  row.bucket = bucket;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rows));
  render();
  toast("Presunuté");
}

/* ---------- Sorting ---------- */
let sortKey = "date";
let sortDir = -1;

/* ---------- Row HTML ---------- */
function rowHtml(r) {
  const thumb = r.photo
    ? `<img class="thumb" src="${r.photo}" alt="" />`
    : `<div class="thumb empty">foto</div>`;

  const today = new Date().toISOString().slice(0, 10);
  const dlClass = r.deadline
    ? (r.deadline < today ? "deadline-past" : "deadline-set")
    : "";

  const statusBadge = r.status
    ? `<span class="badge-select ${statusClass(r.status)}" style="font-size:11px;padding:2px 8px;border-radius:999px;display:inline-block">${esc(r.status)}</span>`
    : `<span style="color:var(--muted)">—</span>`;

  return `<tr data-id="${r.id}">
    <td class="code">${esc(r.code)}</td>
    <td>${esc(r.name)}</td>
    <td>${thumb}</td>
    <td>${linkCell(r.photoLink)}</td>
    <td class="qty-cell">
      <span class="qty-badge ${qtyClass(r.qty)}">${r.qty}</span>
    </td>
    <td>${esc(r.place)}</td>
    <td>${kovanieLabel(r.kovanie)}</td>
    <td>${statusBadge}</td>
    <td>${linkCell(r.webSk)}</td>
    <td>${linkCell(r.webCz)}</td>
    <td>${fmtDate(r.date)}</td>
    <td class="deadline-cell ${dlClass}">${r.deadline ? fmtDate(r.deadline) : ""}</td>
    <td>${esc(r.desc)}</td>
    <td class="price">${r.price ? esc(r.price) + " €" : ""}</td>
    <td class="note-cell" title="${esc(r.note)}">${esc(r.note)}</td>
    <td class="row-actions">
      <select class="row-bucket" data-id="${r.id}" title="Priečinok">
        ${BUCKETS.map((b) => `<option value="${b.v}"${(r.bucket || "") === b.v ? " selected" : ""}>${b.label}</option>`).join("")}
      </select>
    </td>
  </tr>`;
}

/* ---------- Stats ---------- */
function renderStats(rows) {
  const pieces = rows.reduce((s, r) => s + (+r.qty || 0), 0);
  const value  = rows.reduce((s, r) => s + (+r.qty || 0) * (+r.price || 0), 0);
  const low    = rows.filter(r => r.qty > 0 && r.qty <= 3).length;
  const out    = rows.filter(r => r.qty === 0).length;
  document.getElementById("stats").innerHTML = `
    <div class="stat"><div class="num">${rows.length}</div><div class="lbl">Produktov</div></div>
    <div class="stat"><div class="num">${pieces}</div><div class="lbl">Kusov spolu</div></div>
    <div class="stat"><div class="num">${value.toLocaleString("sk-SK")} €</div><div class="lbl">Hodnota</div></div>
    <div class="stat"><div class="num">${out}</div><div class="lbl">Hotové</div></div>`;
}

/* ---------- Render ---------- */
function render() {
  const q     = document.getElementById("searchInput").value.trim().toLowerCase();

  let rows = loadProducts()
    .filter(isSpecialka)
    .filter(p => (p.bucket || "") === currentBucket)
    .filter(p => {
      if (q) {
        const hay = `${p.code} ${p.name} ${p.desc} ${p.note}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

  rows.sort((a, b) => {
    let av = a[sortKey], bv = b[sortKey];
    if (sortKey === "qty" || sortKey === "price") { av = +av; bv = +bv; }
    else { av = String(av).toLowerCase(); bv = String(bv).toLowerCase(); }
    return av < bv ? -1 * sortDir : av > bv ? 1 * sortDir : 0;
  });

  document.getElementById("tbody").innerHTML = rows.map(rowHtml).join("");
  document.getElementById("emptyState").style.display = rows.length ? "none" : "block";
  document.getElementById("specialCount").textContent = rows.length ? `${rows.length} ks` : "";

  // Footer
  const tfoot = document.getElementById("tfoot");
  if (rows.length) {
    const pieces = rows.reduce((s, r) => s + (+r.qty || 0), 0);
    tfoot.innerHTML = `<tr class="sum-row">
      <td colspan="4" class="sum-label">Spolu</td>
      <td class="sum-pieces">${pieces}</td>
      <td colspan="11" class="sum-note">${rows.length} produktov · ${pieces} kusov</td>
    </tr>`;
  } else {
    tfoot.innerHTML = "";
  }

  renderStats(rows);
  renderHeaderArrows();
  renderTabs();
}

function renderHeaderArrows() {
  document.querySelectorAll("thead th[data-sort]").forEach(th => {
    const a = th.querySelector(".arrow");
    if (a) a.textContent = th.dataset.sort === sortKey ? (sortDir === 1 ? "▲" : "▼") : "";
  });
}

/* ---------- Wiring ---------- */
document.getElementById("searchInput").addEventListener("input", render);
document.getElementById("tbody").addEventListener("change", (e) => {
  const sel = e.target.closest(".row-bucket");
  if (sel) moveToBucket(+sel.dataset.id, sel.value);
});

document.querySelectorAll("thead th[data-sort]").forEach(th => {
  th.addEventListener("click", () => {
    if (sortKey === th.dataset.sort) { sortDir *= -1; }
    else { sortKey = th.dataset.sort; sortDir = 1; }
    render();
  });
});

render();
