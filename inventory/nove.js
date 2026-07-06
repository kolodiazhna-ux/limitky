/* Nové produkty — tabuľkový pohľad, rovnaký štýl ako hlavný sklad.
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
  if (v === "Zlaté")      return `<span class="b-gold"  style="font-size:11px;padding:2px 8px;border-radius:999px">Zlaté</span>`;
  if (v === "Strieborné") return `<span class="b-silver" style="font-size:11px;padding:2px 8px;border-radius:999px">Strieborné</span>`;
  return "";
}

function linkCell(url) {
  return url
    ? `<a class="link-open" href="${esc(url)}" target="_blank" rel="noopener" title="${esc(url)}">↗</a>`
    : `<span style="color:var(--muted)">—</span>`;
}

function collectionBadge(code) {
  const c = (code || "").toUpperCase();
  if (c.startsWith("MIA"))  return `<span class="coll-badge coll-mia">MIA</span>`;
  if (c.startsWith("LIL"))  return `<span class="coll-badge coll-lil">LIL</span>`;
  if (c.startsWith("MAR"))  return `<span class="coll-badge coll-mar">MAR</span>`;
  if (c.startsWith("KT"))   return `<span class="coll-badge coll-kt">KT</span>`;
  if (c.startsWith("ADR"))  return `<span class="coll-badge coll-adr">ADR</span>`;
  if (c.startsWith("LEA"))  return `<span class="coll-badge coll-lea">LEA</span>`;
  if (c.startsWith("MIC"))  return `<span class="coll-badge coll-mic">MIC</span>`;
  return "";
}

let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

/* ---------- Dáta ---------- */
function loadProducts() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch (e) { return []; }
}

/* ---------- Filter: čo je "nový produkt" ---------- */
function isNewBag(p) {
  // Ak má produkt uloženú kategóriu (nové produkty), rozhoduje ona.
  if (p.category) return p.category === "nove";
  // Inak (staré dáta) = má v poznámke alebo kóde slovo "NEW" / "NOVE"
  const n = String(p.note || "").toUpperCase();
  const c = String(p.code || "").toUpperCase();
  return n.includes("NEW") || n.includes("NOVE") || c.includes("NEW");
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
      <a class="icon-btn" href="./index.html" title="Otvoriť v sklade">↗</a>
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
  const stock = document.getElementById("stockFilter").value;

  let rows = loadProducts()
    .filter(p => !(p.bucket))
    .filter(isNewBag)
    .filter(p => {
      if (stock === "pripravuj" && p.qty <= 0) return false;
      if (stock === "out" && p.qty !== 0) return false;
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
  document.getElementById("newCount").textContent = rows.length ? `${rows.length} ks` : "";

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
}

function renderHeaderArrows() {
  document.querySelectorAll("thead th[data-sort]").forEach(th => {
    const a = th.querySelector(".arrow");
    if (a) a.textContent = th.dataset.sort === sortKey ? (sortDir === 1 ? "▲" : "▼") : "";
  });
}

/* ---------- Wiring ---------- */
document.getElementById("searchInput").addEventListener("input", render);
document.getElementById("stockFilter").addEventListener("change", render);

document.querySelectorAll("thead th[data-sort]").forEach(th => {
  th.addEventListener("click", () => {
    if (sortKey === th.dataset.sort) { sortDir *= -1; }
    else { sortKey = th.dataset.sort; sortDir = 1; }
    render();
  });
});

render();
