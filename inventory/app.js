/* Dajana Rodriguez — Sklad / Inventár (prototyp)
   Dáta sú zatiaľ uložené lokálne v prehliadači (localStorage).
   Neskôr nahradíme spoločnou databázou (Cloudflare D1) pre tímové úpravy. */

const STORAGE_KEY = "dr_inventory_v2";

const SEED = [
  { id: 1,  code: "MIALIM67-Z",     name: "Mia Limitka 67 Zlatá",                      photo: "", qty: 6,  place: "RRR", date: "2026-01-14", desc: "čierna so zlatým kovaním", price: 275, note: "" },
  { id: 2,  code: "MIALIM68",       name: "Mia Limitka 68 Strieborná",                 photo: "", qty: 7,  place: "RRR", date: "2026-01-21", desc: "nude s výšivkou japonska čerešňa", price: 285, note: "" },
  { id: 3,  code: "KTLIM41",        name: "Kozmetická taštička Limitka 41 Strieborná", photo: "", qty: 4,  place: "RRR", date: "2026-01-21", desc: "nude s výšivkou japonska čerešňa", price: 65,  note: "" },
  { id: 4,  code: "MIALIM69-Z",     name: "Mia Limitka 69 Zlatá",                      photo: "", qty: 10, place: "RRR", date: "2026-01-28", desc: "zlatá s výšivkou japonska čerešňa", price: 285, note: "" },
  { id: 5,  code: "LILLIM57-Z",     name: "Lily Limitka 57 Zlatá",                     photo: "", qty: 3,  place: "RRR", date: "2026-02-04", desc: "ružová s výšivkou", price: 305, note: "" },
  { id: 6,  code: "MIALIM70",       name: "Mia Limitka 70 Strieborná",                 photo: "", qty: 3,  place: "RRR", date: "2026-02-11", desc: "modrá", price: 275, note: "línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe" },
  { id: 7,  code: "MIALIM71",       name: "Mia Limitka 71 Strieborná",                 photo: "", qty: 3,  place: "RRR", date: "2026-02-18", desc: "ružovo/fialová", price: 275, note: "línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe" },
  { id: 8,  code: "LILLIM58",       name: "Lily Limitka 58 Strieborná",                photo: "", qty: 4,  place: "RRR", date: "2026-02-25", desc: "modrá", price: 290, note: "línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe" },
  { id: 9,  code: "LILLIM59",       name: "Lily Limitka 59 Strieborná",                photo: "", qty: 2,  place: "RRR", date: "2026-03-04", desc: "ružovo/fialová", price: 290, note: "línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe" },
  { id: 10, code: "MICLIM10-Z",     name: "Michaela Limitka 10 Zlatá",                 photo: "", qty: 6,  place: "RRR", date: "2026-03-11", desc: "čierna", price: 300, note: "" },
  { id: 11, code: "KTLIM42-Z",      name: "Kozmetická taštička Limitka 42 Zlatá",      photo: "", qty: 2,  place: "RRR", date: "2026-03-18", desc: "bledohnedá", price: 65,  note: "" },
  { id: 12, code: "KTLIM43-Z",      name: "Kozmetická taštička Limitka 43 Zlatá",      photo: "", qty: 3,  place: "RRR", date: "2026-03-18", desc: "tmavohnedá", price: 65,  note: "" },
  { id: 13, code: "LILLIM60-Z",     name: "Lily Limitka 60 Zlatá",                     photo: "", qty: 3,  place: "RRR", date: "2026-03-18", desc: "bledohnedá", price: 305, note: "" },
  { id: 14, code: "MIALIM72-Z",     name: "Mia Limitka 72 Zlatá",                      photo: "", qty: 3,  place: "RRR", date: "2026-03-25", desc: "farebný odlesk", price: 320, note: "" },
  { id: 15, code: "MIALIM73",       name: "Mia Limitka 73 Strieborná",                 photo: "", qty: 4,  place: "RRR", date: "2026-04-01", desc: "marhuľová s výšivkou", price: 320, note: "dá sa personalizovať - nafotiť aj zozadu a nahodiť na web" },
  { id: 16, code: "MIALIM74",       name: "Mia Limitka 74 Strieborná",                 photo: "", qty: 2,  place: "RRR", date: "2026-04-08", desc: "ružová s výšivkou", price: 320, note: "dá sa personalizovať - nafotiť aj zozadu a nahodiť na web" },
  { id: 17, code: "MARLIM15",       name: "Martina Limitka 15 Strieborná",             photo: "", qty: 5,  place: "RRR", date: "2026-04-15", desc: "modrá s výšivkou", price: 305, note: "" },
  { id: 18, code: "",               name: "khloe limitky z DR",                        photo: "", qty: 0,  place: "",    date: "2026-04-22", desc: "", price: 0, note: "" },
  { id: 19, code: "MARLIM16",       name: "Martina Limitka 16 Strieborná",             photo: "", qty: 4,  place: "RRR", date: "2026-04-29", desc: "bledohnedá s výšivkou", price: 305, note: "" },
  { id: 20, code: "LILLIM62",       name: "Lily Limitka 62 Strieborná",                photo: "", qty: 4,  place: "RRR", date: "2026-05-06", desc: "tmavomodrá s výšivkou", price: 305, note: "" },
  { id: 21, code: "MIALIM75",       name: "Mia Limitka 75 Zlatá",                      photo: "", qty: 5,  place: "RRR", date: "2026-05-13", desc: "modrá", price: 275, note: "" },
  { id: 22, code: "MIALIM76",       name: "Mia Limitka 76 Zlatá",                      photo: "", qty: 2,  place: "RRR", date: "2026-05-20", desc: "žltá", price: 275, note: "" },
  { id: 23, code: "MARLIM17",       name: "Martina Limitka 17 Strieborná",             photo: "", qty: 5,  place: "RRR", date: "2026-05-27", desc: "hnedá", price: 305, note: "" },
  { id: 24, code: "MIALIM77-002",   name: "Mia Limitka 77 STRIEBORNA",                 photo: "", qty: 1,  place: "RRR", date: "2026-06-03", desc: "modrá", price: 275, note: "- CHYNBA" },
  { id: 25, code: "MIALIM78",       name: "Mia Limitka 78 Strieborná",                 photo: "", qty: 2,  place: "RRR", date: "2026-06-10", desc: "modrá", price: 275, note: "" },
  { id: 26, code: "MARLIM18",       name: "Martina Limitka 18 Strieborná",             photo: "", qty: 3,  place: "RRR", date: "2026-06-17", desc: "tyrkysová", price: 305, note: "" },
  { id: 27, code: "LILLIM61",       name: "Lily Limitka 61 Strieborná",                photo: "", qty: 3,  place: "RRR", date: "2026-06-24", desc: "bledomodrý s výšivkou", price: 305, note: "" },
  { id: 28, code: "LILLIM63",       name: "Lily Limitka 63 Strieborná",                photo: "", qty: 6,  place: "RRR", date: "2026-07-01", desc: "tyrkysová s výšivkou", price: 305, note: "" },
  { id: 29, code: "LILLIM64-Z",     name: "Lily Limitka 64 Zlatá",                     photo: "", qty: 3,  place: "RRR", date: "2026-07-08", desc: "Bordová s výšivkou", price: 305, note: "" },
  { id: 30, code: "LILLIM55-Z-001", name: "Lily Limitka 55 zlatá",                     photo: "", qty: 1,  place: "RRR", date: "2026-07-15", desc: "Ružová s výšivkou", price: 305, note: "" },
  { id: 31, code: "MIALIM65-Z-001", name: "Mia Limitka 65 zlatá",                      photo: "", qty: 1,  place: "RRR", date: "2026-07-22", desc: "Tmavozelená s výšivkou", price: 320, note: "" },
  { id: 32, code: "MIALIM-Z-043",   name: "Mia Limitka zlatá",                         photo: "", qty: 1,  place: "RRR", date: "2026-07-29", desc: "Bledomodrá s výšivkou", price: 320, note: "" },
  { id: 33, code: "LILLIM65",       name: "Lily Limitka 65 Strieborná",                photo: "", qty: 4,  place: "RRR", date: "2026-08-05", desc: "kráľovská modrá s výšivkou", price: 305, note: "" },
  { id: 34, code: "KTLIM44-Z",      name: "Kozmetická taštička Limitka 44 Zlatá",      photo: "", qty: 2,  place: "RRR", date: "2026-08-12", desc: "farebný odlesk-fialová", price: 60, note: "" },
  { id: 35, code: "KTLIM45-Z",      name: "Kozmetická taštička Limitka 45 Zlatá",      photo: "", qty: 1,  place: "RRR", date: "2026-08-12", desc: "Farebný odlesk", price: 60, note: "" },
  { id: 36, code: "LEALIM1-Z",      name: "Leanka Limitka 1 Zlatá",                    photo: "", qty: 5,  place: "RRR", date: "2026-08-05", desc: "Červená s potlačou", price: 305, note: "" },
  { id: 37, code: "KTLIM46-Z",      name: "Kozmetická taštička Limitka 46 Zlatá",      photo: "", qty: 2,  place: "RRR", date: "2026-08-05", desc: "Červená s potlačou", price: 60, note: "" },
  { id: 38, code: "MARLIM19",       name: "Martina Limitka 19 Strieborná",             photo: "", qty: 6,  place: "RRR", date: "2026-08-12", desc: "Modrá s výšivkou", price: 305, note: "" },
  { id: 39, code: "ADRLIM8",        name: "Adriana Limitka 8 Strieborná",              photo: "", qty: 5,  place: "RRR", date: "2026-08-19", desc: "Cyklamenova s výšivkou", price: 325, note: "" },
];

/* Číselníky (fixné hodnoty pre statusy) */
const PHOTO_STATUSES = ["", "Poslané na fotenie", "Vyfotené"];
const STATUSES = ["", "Výroba", "Bratislava", "Na ceste do Bratislavy", "Na ceste do Partizánskeho", "Partizánske"];
const KOVANIE = ["", "Zlaté", "Strieborné"];

function kovanieClass(v) {
  return v === "Zlaté" ? "b-gold" : v === "Strieborné" ? "b-silver" : "b-empty";
}

function photoStatusClass(v) {
  return v === "Vyfotené" ? "b-ok" : v === "Poslané na fotenie" ? "b-warn" : "b-empty";
}
function statusClass(v) {
  if (v === "Bratislava") return "b-ok";
  if (v === "Partizánske") return "b-blue";
  if (v === "Výroba") return "b-neutral";
  if (v && v.startsWith("Na ceste")) return "b-warn";
  return "b-empty";
}

// Doplní chýbajúce polia (migrácia starších záznamov v localStorage)
function normalize(rows) {
  return rows.map((r) => ({
    photoStatus: "", photoLink: "", transferNo: "", status: "", rowColor: "", bucket: "",
    webSk: "", webCz: "", kovanie: "", ...r,
  }));
}

/* Koše (mäkká archivácia riadkov) */
const BUCKETS = [
  { v: "", label: "Aktívne" },
  { v: "mail", label: "Odoslané na mail" },
  { v: "soldout", label: "Vypredané" },
];
const bucketLabel = (v) => (BUCKETS.find((b) => b.v === v) || {}).label || "";

/* Prednastavené farby riadkov */
const ROW_COLORS = ["", "#efe7f8", "#e3f6ec", "#fdf0dc", "#e2edfb", "#fbe4f0", "#fdecea"];

let currentBucket = "";
let selected = new Set();

let data = load();
let sortKey = "date";
let sortDir = -1; // -1 = desc, 1 = asc
let editingPhoto = "";

/* ---------- Storage ---------- */
function load() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return normalize(JSON.parse(raw));
  } catch (e) {}
  localStorage.setItem(STORAGE_KEY, JSON.stringify(SEED));
  return normalize(structuredClone(SEED));
}
function save() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}
function nextId() {
  return data.reduce((m, r) => Math.max(m, r.id), 0) + 1;
}

/* ---------- Helpers ---------- */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function fmtDate(iso) {
  if (!iso) return "";
  const [y, m, d] = iso.split("-");
  return `${+d}.${+m}.${y}`;
}
function qtyClass(q) { return q <= 0 ? "qty-out" : q <= 3 ? "qty-low" : "qty-ok"; }

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

/* ---------- Filters / sort ---------- */
function getView() {
  const q = $("#searchInput").value.trim().toLowerCase();
  const place = $("#placeFilter").value;
  const stock = $("#stockFilter").value;
  let rows = data.filter((r) => {
    if ((r.bucket || "") !== currentBucket) return false;
    if (place && r.place !== place) return false;
    if (stock === "ok" && r.qty <= 3) return false;
    if (stock === "low" && !(r.qty > 0 && r.qty <= 3)) return false;
    if (stock === "out" && r.qty !== 0) return false;
    if (q) {
      const hay = `${r.code} ${r.name} ${r.desc} ${r.note} ${r.place}`.toLowerCase();
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
  return rows;
}

/* ---------- Render ---------- */
function render() {
  const rows = getView();
  const tbody = $("#tbody");
  tbody.innerHTML = rows.map(rowHtml).join("");
  $("#emptyState").style.display = rows.length ? "none" : "block";
  renderFooter(rows);
  renderTabs();
  renderStats();
  renderCharts();
  renderHeaderArrows();
  bindRowEvents();
}

// Súhrn na konci zoznamu: počet produktov a kusov (sumiek) v aktuálnom výbere
function renderFooter(rows) {
  const tfoot = $("#tfoot");
  if (!tfoot) return;
  if (!rows.length) { tfoot.innerHTML = ""; return; }
  const pieces = rows.reduce((s, r) => s + (+r.qty || 0), 0);
  tfoot.innerHTML = `<tr class="sum-row">
    <td colspan="6" class="sum-label">Spolu v zozname</td>
    <td class="sum-pieces">${pieces}</td>
    <td colspan="11" class="sum-note">${rows.length} ${plural(rows.length, "produkt", "produkty", "produktov")} · ${pieces} ${plural(pieces, "kus", "kusy", "kusov")}</td>
  </tr>`;
}

// Slovenské skloňovanie počtu (1 / 2-4 / 5+)
function plural(n, one, few, many) {
  if (n === 1) return one;
  if (n >= 2 && n <= 4) return few;
  return many;
}

// Iba aktívne (nearchivované) položky pre štatistiky a grafy
const activeRows = () => data.filter((r) => !r.bucket);

function renderTabs() {
  $("#viewTabs").innerHTML = BUCKETS.map((b) => {
    const cnt = data.filter((r) => (r.bucket || "") === b.v).length;
    return `<button class="view-tab ${b.v === currentBucket ? "active" : ""}" data-bucket="${b.v}">
      ${b.label}<span class="cnt">${cnt}</span></button>`;
  }).join("");
  document.querySelectorAll("[data-bucket]").forEach((t) => {
    t.addEventListener("click", () => { currentBucket = t.dataset.bucket; render(); });
  });
}

/* ---------- Charts ---------- */
const CHART_PALETTE = ["#753BBD", "#C1A7E2", "#512D6D", "#9b6fd1", "#d8c6ef", "#6a4a8f", "#b08ed9"];

// Kolekciu odvodíme z prvého slova názvu (Mia, Lily, Michaela, Kozmetická…)
function collectionOf(name) {
  const w = String(name).trim().split(/\s+/)[0] || "Iné";
  return w === "Kozmetická" ? "Taštičky" : w;
}

function groupBy(rows, keyFn, valFn) {
  const map = {};
  rows.forEach((r) => {
    const k = keyFn(r);
    map[k] = (map[k] || 0) + valFn(r);
  });
  return Object.entries(map).sort((a, b) => b[1] - a[1]);
}

function renderCharts() {
  const A = activeRows();
  // Donut: stav zásob
  const ok = A.filter((r) => r.qty > 3).length;
  const low = A.filter((r) => r.qty > 0 && r.qty <= 3).length;
  const out = A.filter((r) => r.qty === 0).length;
  const segs = [
    { label: "Na sklade", value: ok, color: "#2e9e6b" },
    { label: "Nízke zásoby", value: low, color: "#d68910" },
    { label: "Vypredané", value: out, color: "#c0392b" },
  ];
  const total = ok + low + out;
  let acc = 0;
  const stops = segs
    .filter((s) => s.value > 0)
    .map((s) => {
      const from = (acc / total) * 360;
      acc += s.value;
      const to = (acc / total) * 360;
      return `${s.color} ${from}deg ${to}deg`;
    })
    .join(", ");
  const donut = $("#donutStock");
  donut.style.background = total ? `conic-gradient(${stops})` : "var(--smoke)";
  donut.setAttribute("data-total", total);
  $("#legendStock").innerHTML = segs
    .map((s) => `<li><span class="sw" style="background:${s.color}"></span>${s.label}<span class="lv">${s.value}</span></li>`)
    .join("");

  // Bars: hodnota skladu podľa kolekcie
  renderBars("#barsValue", groupBy(A, (r) => collectionOf(r.name), (r) => (+r.qty || 0) * (+r.price || 0)), (v) => `${v.toLocaleString("sk-SK")} €`);
  // Bars: počet kusov podľa kolekcie
  renderBars("#barsQty", groupBy(A, (r) => collectionOf(r.name), (r) => +r.qty || 0), (v) => `${v} ks`);
}

function renderBars(sel, entries, fmt) {
  const max = Math.max(1, ...entries.map((e) => e[1]));
  $(sel).innerHTML = entries
    .map(
      ([label, val], i) => `<div class="bar-row">
        <span class="bar-label" title="${esc(label)}">${esc(label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(val / max) * 100}%;background:linear-gradient(90deg, var(--primary-light), ${CHART_PALETTE[i % CHART_PALETTE.length]})"></div></div>
        <span class="bar-val">${fmt(val)}</span>
      </div>`
    )
    .join("");
}

function selectHtml(field, value, options, classFn) {
  const opts = options
    .map((o) => `<option value="${esc(o)}" ${o === value ? "selected" : ""}>${o || "—"}</option>`)
    .join("");
  return `<select class="badge-select ${classFn(value)}" data-sel="${field}">${opts}</select>`;
}

// Kovanie ako farebné body (bez textu): zlaté / strieborné. Klik = vybrať / zrušiť.
function kovanieCell(id, value) {
  const dot = (val, color, title) =>
    `<button class="kov-dot${value === val ? " on" : ""}" style="--kc:${color}" data-kov="${val}" data-id="${id}" title="${title}"></button>`;
  return `<div class="kov-cell">${dot("Zlaté", "#d4af37", "Zlaté")}${dot("Strieborné", "#aab2bd", "Strieborné")}</div>`;
}

// Kompaktná bunka odkazu: ↗ otvorí v novom okne; ＋ pridá odkaz priamo do daného poľa
function linkCell(id, field, url) {
  return url
    ? `<a class="link-open" href="${esc(url)}" target="_blank" rel="noopener" title="${esc(url)}">↗</a>
       <button class="link-edit" data-linkedit="${id}" data-linkfield="${field}" title="Upraviť odkaz">✎</button>`
    : `<button class="link-add" data-linkedit="${id}" data-linkfield="${field}" title="Pridať odkaz">＋</button>`;
}

function rowHtml(r) {
  const thumb = r.photo
    ? `<img class="thumb" src="${r.photo}" data-photo="${r.id}" alt="" />`
    : `<div class="thumb empty" data-photo="${r.id}">foto</div>`;
  const style = r.rowColor ? ` style="background:${r.rowColor}"` : "";
  const cls = [r.bucket ? "bucketed" : "", selected.has(r.id) ? "selected" : ""].join(" ").trim();
  return `<tr data-id="${r.id}" class="${cls}"${style}>
    <td class="sel-td"><input type="checkbox" class="row-sel" data-sel-id="${r.id}" ${selected.has(r.id) ? "checked" : ""} /></td>
    <td class="code">${esc(r.code)}</td>
    <td class="cell-edit" data-field="name" contenteditable="true">${esc(r.name)}</td>
    <td>${thumb}</td>
    <td class="check-td"><input type="checkbox" class="foto-check" data-fotoid="${r.id}" ${r.photoStatus === "Vyfotené" ? "checked" : ""} title="Vyfotené" /></td>
    <td>${linkCell(r.id, "photoLink", r.photoLink)}</td>
    <td class="qty-cell">
      <button class="qty-step" data-step="-1" data-id="${r.id}" title="−1">−</button>
      <span class="qty-badge ${qtyClass(r.qty)}" data-qtyedit="${r.id}" contenteditable="true" inputmode="numeric">${r.qty}</span>
      <button class="qty-step" data-step="1" data-id="${r.id}" title="+1">+</button>
    </td>
    <td class="cell-edit" data-field="place" contenteditable="true">${esc(r.place)}</td>
    <td>${kovanieCell(r.id, r.kovanie)}</td>
    <td>${selectHtml("status", r.status, STATUSES, statusClass)}</td>
    <td class="cell-edit" data-field="transferNo" contenteditable="true">${esc(r.transferNo)}</td>
    <td>${linkCell(r.id, "webSk", r.webSk)}</td>
    <td>${linkCell(r.id, "webCz", r.webCz)}</td>
    <td>${fmtDate(r.date)}</td>
    <td class="cell-edit" data-field="desc" contenteditable="true">${esc(r.desc)}</td>
    <td class="price cell-edit" data-field="price" contenteditable="true">${esc(r.price)}</td>
    <td class="cell-edit note-cell" data-field="note" contenteditable="true" data-note="${esc(r.note)}">${esc(r.note)}</td>
    <td class="row-actions">
      <button class="icon-btn" data-menu="${r.id}" title="Akcie">&#8943;</button>
    </td>
  </tr>`;
}

function renderStats() {
  const A = activeRows();
  const total = A.length;
  const pieces = A.reduce((s, r) => s + (+r.qty || 0), 0);
  const value = A.reduce((s, r) => s + (+r.qty || 0) * (+r.price || 0), 0);
  const low = A.filter((r) => r.qty > 0 && r.qty <= 3).length;
  const out = A.filter((r) => r.qty === 0).length;
  $("#stats").innerHTML = `
    <div class="stat"><div class="num">${total}</div><div class="lbl">Produktov</div></div>
    <div class="stat"><div class="num">${pieces}</div><div class="lbl">Kusov spolu</div></div>
    <div class="stat"><div class="num">${value.toLocaleString("sk-SK")} €</div><div class="lbl">Hodnota skladu</div></div>
    <div class="stat"><div class="num">${low}</div><div class="lbl">Nízke zásoby</div></div>
    <div class="stat"><div class="num">${out}</div><div class="lbl">Vypredané</div></div>`;
}

function renderHeaderArrows() {
  document.querySelectorAll("thead th[data-sort]").forEach((th) => {
    const a = th.querySelector(".arrow");
    a.textContent = th.dataset.sort === sortKey ? (sortDir === 1 ? "▲" : "▼") : "";
  });
}

/* ---------- Inline edit ---------- */
function bindRowEvents() {
  document.querySelectorAll(".cell-edit").forEach((cell) => {
    cell.addEventListener("blur", () => {
      const tr = cell.closest("tr");
      const id = +tr.dataset.id;
      const field = cell.dataset.field;
      const row = data.find((r) => r.id === id);
      let val = cell.textContent.trim();
      if (field === "price") val = +val || 0;
      if (row[field] === val) return;
      row[field] = val;
      if (field === "note") cell.dataset.note = val; // udržať tooltip aktuálny
      save();
      toast("Uložené");
      if (field === "photoLink") render(); // obnoviť tlačidlo „otvoriť"
    });
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); cell.blur(); }
    });
  });
  document.querySelectorAll("[data-sel]").forEach((sel) => {
    sel.addEventListener("change", () => {
      const id = +sel.closest("tr").dataset.id;
      const field = sel.dataset.sel;
      const row = data.find((r) => r.id === id);
      row[field] = sel.value;
      // prefarbiť bejdž podľa novej hodnoty (teraz už len „status")
      sel.className = "badge-select " + statusClass(sel.value);
      save();
      toast("Uložené");
    });
  });
  // Stav fotenia: jednoduchá galočka (Vyfotené / nič)
  document.querySelectorAll(".foto-check").forEach((c) => {
    c.addEventListener("change", () => {
      const row = data.find((r) => r.id === +c.dataset.fotoid);
      row.photoStatus = c.checked ? "Vyfotené" : "";
      save();
      toast("Uložené");
    });
  });
  // Kovanie: klik na farebný bod = vybrať, opätovný klik = zrušiť
  document.querySelectorAll(".kov-dot").forEach((b) => {
    b.addEventListener("click", () => {
      const row = data.find((r) => r.id === +b.dataset.id);
      row.kovanie = row.kovanie === b.dataset.kov ? "" : b.dataset.kov;
      save();
      const cell = b.closest(".kov-cell");
      cell.querySelectorAll(".kov-dot").forEach((d) =>
        d.classList.toggle("on", d.dataset.kov === row.kovanie)
      );
      toast("Uložené");
    });
  });
  // Ručná zmena počtu kusov: tlačidlá −/+
  document.querySelectorAll(".qty-step").forEach((b) => {
    b.addEventListener("click", () => {
      const row = data.find((r) => r.id === +b.dataset.id);
      row.qty = Math.max(0, (+row.qty || 0) + (+b.dataset.step));
      save(); render();
    });
  });
  // Ručná zmena počtu kusov: priame prepísanie čísla v bunke
  document.querySelectorAll("[data-qtyedit]").forEach((cell) => {
    cell.addEventListener("blur", () => {
      const row = data.find((r) => r.id === +cell.dataset.qtyedit);
      const v = Math.max(0, parseInt(cell.textContent) || 0);
      if (row.qty === v) { cell.textContent = row.qty; return; }
      row.qty = v; save(); render(); toast("Uložené");
    });
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); cell.blur(); }
    });
  });
  document.querySelectorAll("[data-photo]").forEach((el) => {
    el.addEventListener("click", () => uploadPhotoFor(+el.dataset.photo));
  });
  // Náhľad fotky pri prejdení myšou (5× väčšie, mimo orezania tabuľky)
  document.querySelectorAll("img.thumb[data-photo]").forEach((el) => {
    el.addEventListener("mouseenter", () => showPhotoZoom(el));
    el.addEventListener("mousemove", positionPhotoZoom);
    el.addEventListener("mouseleave", hidePhotoZoom);
  });
  // Zväčšenie textu pri prejdení myšou (mimo orezania tabuľky)
  document.querySelectorAll("td.note-cell").forEach((el) => {
    el.addEventListener("mouseenter", (e) => showTextZoom(el, e));
    el.addEventListener("mousemove", positionTextZoom);
    el.addEventListener("mouseleave", hideTextZoom);
  });
  document.querySelectorAll("[data-menu]").forEach((b) => {
    b.addEventListener("click", (e) => { e.stopPropagation(); openRowMenu(+b.dataset.menu, b); });
  });
  document.querySelectorAll("[data-linkedit]").forEach((b) => {
    b.addEventListener("click", () => {
      const row = data.find((r) => r.id === +b.dataset.linkedit);
      const field = b.dataset.linkfield; // photoLink / webSk / webCz
      const labels = { photoLink: "odkaz na fotky", webSk: "odkaz Web SK", webCz: "odkaz Web CZ" };
      const current = row[field] || "";
      const val = window.prompt(`Vložte ${labels[field] || "odkaz"}:`, current);
      if (val === null) return; // zrušené
      row[field] = val.trim();
      save();
      render();
      toast(row[field] ? "Odkaz uložený" : "Odkaz odstránený");
    });
  });
  // výber riadkov
  document.querySelectorAll(".row-sel").forEach((c) => {
    c.addEventListener("change", () => {
      const id = +c.dataset.selId;
      c.checked ? selected.add(id) : selected.delete(id);
      c.closest("tr").classList.toggle("selected", c.checked);
      renderBulkBar();
    });
  });
  const visibleIds = getView().map((r) => r.id);
  const selAll = $("#selAll");
  if (selAll) selAll.checked = visibleIds.length > 0 && visibleIds.every((id) => selected.has(id));
}

/* ---------- Výber riadkov + hromadné akcie ---------- */
function applyToSelected(fn, msg) {
  data.forEach((r) => { if (selected.has(r.id)) fn(r); });
  save(); render(); if (msg) toast(msg);
}
function renderBulkBar() {
  const bar = $("#bulkBar");
  if (!selected.size) { bar.classList.remove("show"); return; }
  const swatches = ROW_COLORS.map((c) =>
    c === ""
      ? `<div class="bulk-swatch none" data-bcolor="" title="Žiadna">✕</div>`
      : `<div class="bulk-swatch" style="background:${c}" data-bcolor="${c}"></div>`
  ).join("");
  bar.innerHTML = `
    <span class="cnt">${selected.size} vybrané</span>
    <div class="bulk-swatches">${swatches}</div>
    <button class="bulk-btn" data-bact="mail">✉️ Na mail</button>
    <button class="bulk-btn" data-bact="soldout">🏷️ Vypredané</button>
    <button class="bulk-btn" data-bact="active">↩️ Aktívne</button>
    <button class="bulk-btn danger" data-bact="del">🗑️ Vymazať</button>
    <button class="bulk-btn" data-bact="clear">✕ Zrušiť výber</button>`;
  bar.classList.add("show");
  bar.querySelectorAll("[data-bcolor]").forEach((sw) =>
    sw.addEventListener("click", () => applyToSelected((r) => (r.rowColor = sw.dataset.bcolor), "Farba zmenená"))
  );
  bar.querySelectorAll("[data-bact]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const act = btn.dataset.bact;
      if (act === "clear") { selected.clear(); render(); return; }
      if (act === "del") {
        if (!confirm(`Vymazať ${selected.size} vybraných produktov?`)) return;
        data = data.filter((r) => !selected.has(r.id));
        selected.clear(); save(); render(); toast("Vymazané"); return;
      }
      const bucket = act === "active" ? "" : act;
      applyToSelected((r) => (r.bucket = bucket), "Presunuté");
      selected.clear(); render();
    })
  );
}

/* ---------- Row menu (farba + koše) ---------- */
function openRowMenu(id, anchor) {
  const row = data.find((r) => r.id === id);
  const menu = $("#rowMenu");
  const swatches = ROW_COLORS.map((c) =>
    c === ""
      ? `<div class="rm-swatch none" data-color="" title="Žiadna">✕</div>`
      : `<div class="rm-swatch" style="background:${c}" data-color="${c}"></div>`
  ).join("");
  const bucketItems = [];
  if (row.bucket !== "mail") bucketItems.push(`<button class="rm-item" data-act="mail">✉️ Odoslané na mail</button>`);
  if (row.bucket !== "soldout") bucketItems.push(`<button class="rm-item" data-act="soldout">🏷️ Vypredané</button>`);
  if (row.bucket) bucketItems.push(`<button class="rm-item" data-act="active">↩️ Vrátiť medzi aktívne</button>`);

  menu.innerHTML = `
    <div class="rm-title">Farba riadku</div>
    <div class="rm-swatches">${swatches}</div>
    <div class="rm-sep"></div>
    ${bucketItems.join("")}
    <div class="rm-sep"></div>
    ${row.photo ? `<button class="rm-item danger" data-act="delphoto">🖼️ Vymazať fotku</button>` : ""}
    <button class="rm-item" data-act="edit">✏️ Upraviť</button>
    <button class="rm-item danger" data-act="del">🗑️ Vymazať</button>`;

  // pozícia pri tlačidle
  const r = anchor.getBoundingClientRect();
  menu.style.top = `${r.bottom + 6}px`;
  menu.style.left = `${Math.min(r.left, window.innerWidth - 220)}px`;
  menu.classList.add("open");

  menu.querySelectorAll("[data-color]").forEach((sw) => {
    sw.addEventListener("click", () => { row.rowColor = sw.dataset.color; save(); render(); closeRowMenu(); });
  });
  menu.querySelectorAll("[data-act]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const act = btn.dataset.act;
      if (act === "edit") { openModal(id); }
      else if (act === "del") { del(id); }
      else if (act === "delphoto") {
        if (confirm("Naozaj vymazať fotku?")) { row.photo = ""; save(); render(); toast("Fotka vymazaná"); }
      }
      else if (act === "active") { row.bucket = ""; save(); render(); toast("Vrátené medzi aktívne"); }
      else { row.bucket = act; save(); render(); toast(act === "mail" ? "Presunuté: Odoslané na mail" : "Presunuté: Vypredané"); }
      closeRowMenu();
    });
  });
}
function closeRowMenu() { $("#rowMenu").classList.remove("open"); }
document.addEventListener("click", (e) => {
  if (!e.target.closest("#rowMenu") && !e.target.closest("[data-menu]")) closeRowMenu();
});

function uploadPhotoFor(id) {
  const inp = document.createElement("input");
  inp.type = "file"; inp.accept = "image/*";
  inp.onchange = () => {
    const f = inp.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      const row = data.find((r) => r.id === id);
      row.photo = reader.result;
      save(); render(); toast("Fotka pridaná");
    };
    reader.readAsDataURL(f);
  };
  inp.click();
}

// ── Náhľad fotky pri prejdení myšou ─────────────────────────────
let photoZoomEl = null;
function showPhotoZoom(thumb) {
  if (!photoZoomEl) {
    photoZoomEl = document.createElement("img");
    photoZoomEl.className = "photo-zoom";
    document.body.appendChild(photoZoomEl);
  }
  photoZoomEl.src = thumb.src;
  photoZoomEl.style.display = "block";
  positionPhotoZoom({ clientX: thumb.getBoundingClientRect().right, clientY: thumb.getBoundingClientRect().top });
}
function positionPhotoZoom(e) {
  if (!photoZoomEl) return;
  const size = 360, pad = 16;
  let x = e.clientX + pad;
  let y = e.clientY + pad;
  if (x + size > window.innerWidth)  x = e.clientX - size - pad;
  if (y + size > window.innerHeight) y = window.innerHeight - size - pad;
  if (y < pad) y = pad;
  photoZoomEl.style.left = x + "px";
  photoZoomEl.style.top  = y + "px";
}
function hidePhotoZoom() {
  if (photoZoomEl) photoZoomEl.style.display = "none";
}

// ── Zväčšenie textu pri prejdení myšou ──────────────────────────
let textZoomEl = null;
function showTextZoom(cell, e) {
  // počas úpravy bunky náhľad nezobrazovať
  if (cell.isContentEditable && document.activeElement === cell) return;
  const txt = (cell.textContent || "").trim();
  if (!txt) return;
  if (!textZoomEl) {
    textZoomEl = document.createElement("div");
    textZoomEl.className = "text-zoom";
    document.body.appendChild(textZoomEl);
  }
  textZoomEl.textContent = txt;
  textZoomEl.style.display = "block";
  positionTextZoom(e);
}
function positionTextZoom(e) {
  if (!textZoomEl || textZoomEl.style.display === "none") return;
  const pad = 14;
  const w = textZoomEl.offsetWidth, h = textZoomEl.offsetHeight;
  let x = e.clientX + pad;
  let y = e.clientY + pad;
  if (x + w > window.innerWidth)  x = e.clientX - w - pad;
  if (y + h > window.innerHeight) y = window.innerHeight - h - pad;
  if (y < pad) y = pad;
  textZoomEl.style.left = x + "px";
  textZoomEl.style.top  = y + "px";
}
function hideTextZoom() {
  if (textZoomEl) textZoomEl.style.display = "none";
}

function del(id) {
  const row = data.find((r) => r.id === id);
  if (!confirm(`Naozaj vymazať „${row.name}"?`)) return;
  data = data.filter((r) => r.id !== id);
  save(); render(); toast("Vymazané");
}

/* ---------- Modal ---------- */
function openModal(id) {
  editingPhoto = "";
  const row = id ? data.find((r) => r.id === id) : null;
  $("#modalTitle").textContent = row ? "Upraviť produkt" : "Nový produkt";
  $("#f-id").value = row ? row.id : "";
  $("#f-code").value = row ? row.code : "";
  $("#f-name").value = row ? row.name : "";
  $("#f-qty").value = row ? row.qty : "";
  $("#f-place").value = row ? row.place : "RRR";
  $("#f-date").value = row ? row.date : new Date().toISOString().slice(0, 10);
  $("#f-desc").value = row ? row.desc : "";
  $("#f-price").value = row ? row.price : "";
  $("#f-note").value = row ? row.note : "";
  $("#f-status").value = row ? row.status : "";
  $("#f-kovanie").value = row ? row.kovanie : "";
  $("#f-transfer").value = row ? row.transferNo : "";
  $("#f-photoStatus").value = row ? row.photoStatus : "";
  $("#f-photoLink").value = row ? row.photoLink : "";
  $("#f-webSk").value = row ? row.webSk : "";
  $("#f-webCz").value = row ? row.webCz : "";
  editingPhoto = row ? row.photo : "";
  $("#photoPreview").innerHTML = editingPhoto ? `<img src="${editingPhoto}" />` : "Kliknite pre nahratie fotky";
  $("#photoRemoveBtn").style.display = editingPhoto ? "inline-flex" : "none";
  $("#modalBg").classList.add("open");
}
function closeModal() { $("#modalBg").classList.remove("open"); }

function saveModal() {
  const id = $("#f-id").value;
  const rec = {
    code: $("#f-code").value.trim(),
    name: $("#f-name").value.trim(),
    qty: Math.max(0, parseInt($("#f-qty").value) || 0),
    place: $("#f-place").value.trim(),
    date: $("#f-date").value,
    desc: $("#f-desc").value.trim(),
    price: +$("#f-price").value || 0,
    note: $("#f-note").value.trim(),
    status: $("#f-status").value,
    kovanie: $("#f-kovanie").value,
    transferNo: $("#f-transfer").value.trim(),
    photoStatus: $("#f-photoStatus").value,
    photoLink: $("#f-photoLink").value.trim(),
    webSk: $("#f-webSk").value.trim(),
    webCz: $("#f-webCz").value.trim(),
    photo: editingPhoto || "",
  };
  if (!rec.code || !rec.name) { toast("Vyplňte Kód a Názov"); return; }
  if (id) {
    Object.assign(data.find((r) => r.id === +id), rec);
  } else {
    data.push({ id: nextId(), ...rec });
  }
  save(); closeModal(); render(); toast("Uložené");
}

/* ---------- Export ---------- */
function exportCSV() {
  const cols = ["code", "name", "qty", "place", "kovanie", "status", "transferNo", "photoStatus", "photoLink", "webSk", "webCz", "date", "desc", "price", "note", "bucket"];
  const head = ["Kód", "Názov produktu", "Počet ks", "Miesto výroby", "Kovanie", "Stav", "Číslo presunu", "Stav fotenia", "Odkaz na fotky", "Web SK", "Web CZ", "Dátum uverejnenia", "Popis", "Cena", "Poznámka", "Kôš"];
  const lines = [head.join(",")];
  data.forEach((r) => {
    lines.push(cols.map((c) => `"${String(r[c] ?? "").replace(/"/g, '""')}"`).join(","));
  });
  const blob = new Blob(["\uFEFF" + lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `dajana-sklad-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
}

/* ---------- Init ---------- */
function initPlaceFilter() {
  const places = [...new Set(data.map((r) => r.place).filter(Boolean))].sort();
  const sel = $("#placeFilter");
  places.forEach((p) => {
    const o = document.createElement("option");
    o.value = p; o.textContent = p; sel.appendChild(o);
  });
}
function fillModalSelects() {
  const opt = (o) => `<option value="${esc(o)}">${o || "—"}</option>`;
  $("#f-status").innerHTML = STATUSES.map(opt).join("");
  $("#f-kovanie").innerHTML = KOVANIE.map(opt).join("");
  $("#f-photoStatus").innerHTML = PHOTO_STATUSES.map(opt).join("");
}
function initPresence() {
  const people = [{ n: "Dajana", c: "#753BBD" }, { n: "Oli", c: "#512D6D" }, { n: "Tím", c: "#C1A7E2" }];
  $("#avatars").innerHTML = people.map((p) => `<div class="av" style="background:${p.c}">${p.n[0]}</div>`).join("");
  $("#presenceText").textContent = `${people.length} online`;
}

document.querySelectorAll("thead th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const k = th.dataset.sort;
    if (sortKey === k) sortDir *= -1; else { sortKey = k; sortDir = 1; }
    render();
  });
});
$("#selAll").addEventListener("change", (e) => {
  const ids = getView().map((r) => r.id);
  if (e.target.checked) ids.forEach((id) => selected.add(id));
  else ids.forEach((id) => selected.delete(id));
  render();
  renderBulkBar();
});
$("#searchInput").addEventListener("input", render);
$("#placeFilter").addEventListener("change", render);
$("#stockFilter").addEventListener("change", render);
$("#addBtn").addEventListener("click", () => openModal(null));
$("#exportBtn").addEventListener("click", exportCSV);
$("#cancelBtn").addEventListener("click", closeModal);
$("#saveBtn").addEventListener("click", saveModal);
$("#modalBg").addEventListener("click", (e) => { if (e.target.id === "modalBg") closeModal(); });
$("#photoDrop").addEventListener("click", () => $("#f-photo").click());
$("#f-photo").addEventListener("change", () => {
  const f = $("#f-photo").files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => {
    editingPhoto = reader.result;
    $("#photoPreview").innerHTML = `<img src="${editingPhoto}" />`;
    $("#photoRemoveBtn").style.display = "inline-flex";
  };
  reader.readAsDataURL(f);
});
$("#photoRemoveBtn").addEventListener("click", () => {
  editingPhoto = "";
  $("#f-photo").value = "";
  $("#photoPreview").innerHTML = "Kliknite pre nahratie fotky";
  $("#photoRemoveBtn").style.display = "none";
});

initPlaceFilter();
fillModalSelects();
initPresence();
render();
