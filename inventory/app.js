/* Dajana Rodriguez — Sklad / Inventár (prototyp)
   Dáta sú zatiaľ uložené lokálne v prehliadači (localStorage).
   Neskôr nahradíme spoločnou databázou (Cloudflare D1) pre tímové úpravy. */

const STORAGE_KEY = "dr_inventory_v2";

/* ---------- Fotky v IndexedDB ----------
   Fotky (data URL) sú veľké, preto ich NEUKLADÁME do localStorage (limit ~5 MB),
   ale do IndexedDB (stovky MB). V pamäti držíme cache: id -> data URL. */
const PHOTO_DB = "dr_photos";
const PHOTO_STORE = "photos";
let photoCache = {};
let _photoDB = null;

function openPhotoDB() {
  return new Promise((resolve, reject) => {
    if (_photoDB) return resolve(_photoDB);
    const req = indexedDB.open(PHOTO_DB, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(PHOTO_STORE)) {
        req.result.createObjectStore(PHOTO_STORE);
      }
    };
    req.onsuccess = () => { _photoDB = req.result; resolve(_photoDB); };
    req.onerror = () => reject(req.error);
  });
}

async function loadAllPhotos() {
  try {
    const db = await openPhotoDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(PHOTO_STORE, "readonly");
      const store = tx.objectStore(PHOTO_STORE);
      const req = store.openCursor();
      req.onsuccess = () => {
        const cur = req.result;
        if (cur) { photoCache[cur.key] = cur.value; cur.continue(); }
        else resolve();
      };
      req.onerror = () => reject(req.error);
    });
  } catch (e) { /* IndexedDB nedostupné – fotky nebudú */ }
}

async function idbPut(id, dataUrl) {
  const db = await openPhotoDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(PHOTO_STORE, "readwrite");
    tx.objectStore(PHOTO_STORE).put(dataUrl, id);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}

async function idbDel(id) {
  const db = await openPhotoDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(PHOTO_STORE, "readwrite");
    tx.objectStore(PHOTO_STORE).delete(id);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}

// Prečíta fotku z cache pre daný záznam.
function photoOf(r) { return photoCache[r.id] || ""; }

// Uloží / vymaže fotku (cache + IndexedDB). Vráti true/false.
async function setPhoto(id, dataUrl) {
  try {
    if (dataUrl) { await idbPut(id, dataUrl); photoCache[id] = dataUrl; }
    else { await idbDel(id); delete photoCache[id]; }
    savePhotoToServer(id, dataUrl); // spoločná databáza – synchronizácia na pozadí
    return true;
  } catch (e) {
    toast("Fotku sa nepodarilo uložiť");
    return false;
  }
}

/* Jednorazovo: presunúť staré fotky z localStorage (r.photo) do IndexedDB,
   aby sa uvoľnila pamäť. Beží pred prvým vykreslením. */
async function migratePhotosToIDB(rows) {
  let moved = false;
  for (const r of rows) {
    if (r.photo && String(r.photo).startsWith("data:")) {
      const ok = await setPhoto(r.id, r.photo);
      if (ok) { r.photo = ""; moved = true; }
    }
  }
  if (moved) { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(rows)); } catch (e) {} }
}

/* ---------- Spoločná databáza (server) ----------
   Server (Cloudflare D1) je zdroj pravdy – dáta sú spoločné pre všetky zariadenia.
   localStorage + IndexedDB slúžia ako rýchla lokálna kópia a záloha pre prácu offline.
   Model: celý zoznam produktov je jeden JSON dokument (PUT /api/products),
   fotky sú uložené samostatne (PUT/DELETE /api/photos/:id). */
const API_PRODUCTS = "/api/products";
const API_PHOTOS   = "/api/photos";

// authFetch je definované v auth.js (pridá prihlasovací token). Fallback na fetch.
function apiFetch(url, opts) {
  return (typeof authFetch === "function" ? authFetch : fetch)(url, opts);
}

// Uloží celý zoznam produktov na server. Beží na pozadí, chyby neblokujú appku.
async function saveToServer() {
  try {
    const res = await apiFetch(API_PRODUCTS, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return res.ok;
  } catch (e) { return false; }
}

// Uloží (dataUrl) alebo vymaže (prázdne) jednu fotku na serveri.
async function savePhotoToServer(id, dataUrl) {
  try {
    if (dataUrl) {
      await apiFetch(`${API_PHOTOS}/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: dataUrl }),
      });
    } else {
      await apiFetch(`${API_PHOTOS}/${id}`, { method: "DELETE" });
    }
    return true;
  } catch (e) { return false; }
}

// Stiahne všetky fotky zo servera do cache + IndexedDB.
// Vráti množinu (Set) ID fotiek, ktoré server má.
async function pullPhotosFromServer() {
  const onServer = new Set();
  try {
    const res = await apiFetch(API_PHOTOS);
    if (!res.ok) return onServer;
    const map = await res.json(); // { id: dataUrl }
    for (const id in map) {
      onServer.add(String(id));
      photoCache[id] = map[id];
      try { await idbPut(id, map[id]); } catch (e) {}
    }
  } catch (e) {}
  return onServer;
}

// Nahrá všetky lokálne fotky na server (jednorazovo, keď je server prázdny).
async function pushAllPhotosToServer() {
  for (const id in photoCache) {
    if (photoCache[id]) await savePhotoToServer(id, photoCache[id]);
  }
}

/* Manuálna záloha: nahrá VŠETKY fotky z tohto zariadenia do spoločnej databázy.
   Spustí sa tlačidlom „☁️ Zálohovať fotky". Je to spoľahlivé riešenie, keď sa
   fotky z nejakého dôvodu nedostali na server automaticky. */
async function backupPhotos(btn) {
  const ids = Object.keys(photoCache).filter((id) => photoCache[id]);
  if (ids.length === 0) {
    toast("V tomto zariadení nie sú uložené žiadne fotky.");
    return;
  }
  const origHTML = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.textContent = `Nahrávam 0/${ids.length}…`; }
  let ok = 0;
  for (let i = 0; i < ids.length; i++) {
    const done = await savePhotoToServer(ids[i], photoCache[ids[i]]);
    if (done) ok++;
    if (btn) btn.textContent = `Nahrávam ${i + 1}/${ids.length}…`;
  }
  if (btn) { btn.disabled = false; btn.innerHTML = origHTML; }
  toast(`Hotovo — ${ok} z ${ids.length} fotiek je v spoločnej databáze.`);
}

/* „Ремонт“ fotiek: ak máme fotku lokálne (v tomto prehliadači), ale na serveri
   chýba, nahráme ju. Vďaka tomu sa fotky nazbierané na jednom zariadení
   dostanú do spoločnej databázy aj keď server už má produkty. */
async function repairMissingPhotos(onServer) {
  let fixed = 0;
  for (const id in photoCache) {
    if (photoCache[id] && !onServer.has(String(id))) {
      const ok = await savePhotoToServer(id, photoCache[id]);
      if (ok) fixed++;
    }
  }
  if (fixed > 0) toast(`Obnovených ${fixed} fotiek do spoločnej databázy.`);
}

/* ── Automatická obnova zo servera ─────────────────────────────────────────
   Dlho otvorená stránka by inak držala starú kópiu dát a pri najbližšej
   úprave by prepísala zmeny z iných zariadení (napr. archiváciu vo Fotení).
   Preto sa dáta každých 30 s potichu obnovia zo servera — ale nie počas
   úprav (otvorený formulár, kurzor v bunke) ani tesne po vlastnej zmene. */
let lastLocalChange = 0;
let lastServerJson  = "";

async function refreshFromServer() {
  if (document.hidden) return;                              // karta v pozadí
  if (Date.now() - lastLocalChange < 15000) return;         // práve sme ukladali
  if ($("#modalBg")?.classList.contains("open")) return;    // otvorený formulár
  const ae = document.activeElement;
  if (ae && ae.closest && ae.closest(".table-wrap") &&
      (ae.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(ae.tagName))) return; // prebieha úprava bunky

  let rows;
  try {
    const res = await apiFetch(API_PRODUCTS);
    if (!res.ok) return;
    rows = await res.json();
  } catch (e) { return; }
  if (!Array.isArray(rows) || rows.length === 0) return;

  const j = JSON.stringify(rows);
  if (j === lastServerJson) return;                         // nič nové
  if (Date.now() - lastLocalChange < 15000) return;         // zmena počas sťahovania
  lastServerJson = j;
  data = normalize(rows);
  takeSnapshot();
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
  render();
}
setInterval(refreshFromServer, 30000);

/* Zosúladí lokálne dáta so serverom:
   • server má dáta  → server vyhráva (spoločný stav pre všetkých),
   • server prázdny + máme lokálne → nahráme lokálne (prvé zariadenie). */
async function syncFromServer() {
  let serverRows;
  try {
    const res = await apiFetch(API_PRODUCTS);
    if (!res.ok) return;          // API nedostupné → ostávame na lokálnych dátach
    serverRows = await res.json();
  } catch (e) { return; }         // offline → lokálne dáta
  if (!Array.isArray(serverRows)) return;

  if (serverRows.length > 0) {
    data = normalize(serverRows);
    takeSnapshot();
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
    const onServer = await pullPhotosFromServer();
    await repairMissingPhotos(onServer); // dorovná fotky, čo sú lokálne ale chýbajú na serveri
    render();
  } else if (data.length > 0) {
    await saveToServer();
    await pushAllPhotosToServer();
  }
}

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
  { id: 40, code: "LILLIM66",       name: "Lily Limitka 66 Strieborná",               photo: "", qty: 4,  place: "RRR", date: "2026-08-26", desc: "Fuksia s výšivkou",        price: 305, note: "" },
];

/* RDF (Raul Del Fuego) — pánska línia.
   Pôvodné RDF produkty boli na želanie odstránené (viď load() – dr_rdf_clear_v1). */
const RDF_SEED = [];
const RDF_SEED2 = [];

/* Špecialitky — doplnia sa raz do dát (viď load()).
   Názov obsahuje "Špecialitka", takže ich stránka Špeciálka zachytí. */
const SPEC_SEED = [
  { code: "EMASPE1", name: "Ema Špecialitka 1 Strieborná", kovanie: "Strieborné",
    desc: "model ako BOHEMIAN, koža Lucy Ja orchidea, podšívka ottawa béžová, kovanie strieborné",
    note: "logo kovové ako má EMA Bohemian" },
];

/* Limitky z tabuľky (doplnia sa raz do dát – viď load()).
   STAV "HOTOVE" v tabuľke = kôš/priečinok "Hotové" (bucket: "soldout"). */
const LIM_SEED = [
  { code: "KHLLIM7",   name: "Khloe Limitka 7 Strieborná", category: "specialka", place: "DR", kovanie: "Strieborné",
    desc: "svetlofialová s výšivkou", note: "strieborné razenie na klope (ako na Bohemian)" },
  { code: "KHLLIM8-Z", name: "Khloe Limitka 8 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    desc: "svetlozelená s výšivkou", note: "zlaté razenie na klope (ako na Bohemian)" },
  { code: "BELLIM4-Z", name: "Bella Limitka 4 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 10, price: 270, date: "2026-05-18", bucket: "soldout",
    desc: "fialová koža (willer 86372), bude všetko ako Bohemian, logo kovové ako na Bohemian, kovanie zlaté, podšívka……????",
    note: "logo kovové na PD ako na BOHEMIAN" },
  { code: "LARLIM2-Z", name: "Lara Limitka 2 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 6, price: 310, date: "2026-05-25", bucket: "soldout",
    desc: "béžová laková bez výšivky", note: "logo DR na klope" },
  { code: "KARILIM2-Z", name: "Karin II Limitka 2 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 4, price: 310, date: "2026-06-01", bucket: "soldout",
    desc: "koža mentolovo zelená, podšívka béžová, kovanie zlaté, pop ako contessa, logo kovové",
    note: "logo DR na PD ako Contessa" },
  { code: "LIALIM5-Z", name: "Lia Limitka 5 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 10, price: 380, date: "2026-06-22", bucket: "soldout",
    desc: "koža limitková žltá, kovanie zlaté, telo ako IRIS, POP bude ako POP TRINITY vyšívaný (pripnutý ako doplnok), logo razené na KLOPE - zlaté - ako na IRIS, putká sú ako na BOHEMIAN nie ako na IRIS-e",
    note: "logo razené ZLATÉ na KLOPE ako na IRIS" },
  { code: "KHLLIM10-Z", name: "Khloe Limitka 10 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 15, price: 200, date: "2026-07-06", bucket: "soldout",
    desc: "koža limitková ružová, model ako Bohemian, podšívka béžová OTTAWA, kovanie zlaté",
    note: "logo razené ZLATÉ na KLOPE ako na Bohemian" },
  { code: "VIKLIM2-Z", name: "Viktoria Limitka 2 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 20, price: 350, date: "2026-07-20", bucket: "soldout",
    desc: "fialovo-modrá s dúhovým efektom ALARIS", note: "logo DR na PD" },
  { code: "LARLIM3-Z", name: "Lara Limitka 3 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 11, price: 370, date: "2026-07-20", bucket: "soldout",
    desc: "koža limitková ALARIS (tmavá fialová s dúhovým odleskom), kovanie zlaté, logo kovové na klope ako ATLANTIS, podšívka tmavofialová ottawa, zips presný 18cm čierny OOK D580",
    note: "logo kovové na klope ako na ATLANTIS" },
  { code: "LIALIM6-Z", name: "Lia Limitka 6 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 20,
    desc: "koža cerulean trill, model ako Lady D, podšívka ottawa béžová, kovanie zlaté, razenie ZLATÉ na KLOPE ako Bohemian?",
    note: "logo razené ZLATÉ na KLOPE ako na Bohemian" },
  { code: "VANDLIM1-Z", name: "Vanda Limitka 1 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 4, price: 390, bucket: "soldout",
    desc: "koža zelený krzený lak, podšívka ????, kovanie zlaté, logo kovové ako na Atlantise, robená v štýle ATLANTIS len bez rtľoviny",
    note: "logo kovové na PD ako na ATLANTISE" },
  { code: "LIMLIM3-Z", name: "Lima Limitka 3 Zlatá (LIMA Gatsby)", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 20,
    desc: "koža limitková jasná zelená, model ako Bohemian len s výšivkou na PD, logo razené zlaté na klope ako na PRIMA",
    note: "logo razené ZLATÉ na klope ako na PRIMA" },
  { code: "KARLIM4-Z", name: "Karin Limitka 4 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 4,
    desc: "koža limitková telová, model presne ako TRINITY, kovanie zlaté, výšivka presne ako TRINITY a nit vyšívacia sa doladí podľa kože (aby bola tón v tón), zips 3mm + 5mm OOK hnedý ako na TRINITY kolek. (vybrala Lubka s Ivkou v Bošanoch)",
    note: "" },
  { code: "BELLIM5-Z", name: "Bella Limitka 5 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    qty: 20,
    desc: "koža hladká zlatá (z BELLY ORION), model ako CONTESSA - razenie na klope NA SUROVO, kovanie zlaté, podšívka béžová OTTAWA, zips presný kovový sand",
    note: "logo razené na klope na SUROVO" },
  { code: "VIVLIM2", name: "Vivienne Limitka 2 Strieborná (VIVIENNE Giada)", category: "specialka", place: "DR", kovanie: "Strieborné",
    qty: 2,
    desc: "koža limitková tmavozelená, model presne ako VIVIENNE Bohemian, podšívka ottawa ata béžová, zipsy sand plastové",
    note: "logo kovové na PD ako na BOHEMIAN" },
  { code: "LIMLIM4", name: "Lima Limitka 4 Strieborná", category: "specialka", place: "DR", kovanie: "Strieborné",
    qty: 9,
    desc: "koža limitková ružova ako CONTESSA len HLADKÁ, kovanie strieborne, ako PRIMA - výšivka PD + klopa, podš. OTTAWA ATA béžová",
    note: "logo ako PRIMA - razené na klope NA SUROVO" },
  { code: "POMLIM4-Z", name: "Pompadurka Limitka 4 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    desc: "koža limitková zlatá (mäkká), vyšívané PZD, kovanie zlaté, logo razené NA SUROVO, podšívka OTTAWA ATA béžová",
    note: "logo razené NA SUROVO na PD" },
  { code: "VIKLIM3-Z", name: "Viktoria Limitka 3 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    desc: "koža biela akákoľvek, kovanie zlaté, logo razené ZLATÉ na PD ako Bohemian, podš. OTTAWA ATA béžová",
    note: "loro razené ZLATÉ na PD ako Bohemian" },
  { code: "MIALIM79-Z", name: "Mia Limitka 79 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    desc: "koža zelená, výšivka vlčie maky len iné farby nití, všetko ako vlčie maky",
    note: "logo kovové ako vlčie maky" },
  { code: "KRILIM1-Z", name: "Kristýna Limitka 1 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    desc: "model ako PEONY, koža horčicová TRESOR 4994, kovanie zlaté, podšívka ottawa ata béžová, logo razené na držiaku ZLATÉ",
    note: "logo razené ZLATÉ na držiaku ako PEONY" },
  { code: "BELLIM6-Z", name: "Bella Limitka 6 Zlatá", category: "specialka", place: "DR", kovanie: "Zlaté",
    desc: "model ako BOHEMIAN, koža horčicová TRESOR 4994, kovanie zlaté, podš. ottawa ata béžová, zips 3mm plastový sand k podšívke, logo kovové ako na Bohemian",
    note: "logo kovové ako BELLE Bohemian" },
];

/* Číselníky (fixné hodnoty pre statusy) */
const PHOTO_STATUSES = ["", "Poslané na fotenie", "Vyfotené"];
const STATUSES = ["", "Bošany", "V presune do BA", "Bratislava", "V presune do PE", "Partizánske"];
// Prevod starých hodnôt Mesto na nové (aby existujúce produkty sedeli s novým zoznamom)
const STATUS_MIGRATE = { "Výroba": "Bošany", "Na ceste do Bratislavy": "V presune do BA", "Na ceste do Partizánskeho": "V presune do PE" };
const KOVANIE = ["", "Zlaté", "Strieborné"];

/* ── Etapy procesu (rovnaké ako vo Fotení) ────────────────────────────────
   Horné záložky = 4 etapy pipeline. Etapa sa počíta z fotoStage (+refoto),
   takže Sklad aj Fotenie ukazujú to isté a schválenie od Mirky sa prejaví tu. */
const WF_STAGES = [
  { v: "new",      label: "🆕 Nové zadania" },
  { v: "progress", label: "📸 Fotí sa" },
  { v: "approval", label: "⏳ Čaká na schválenie" },
  { v: "done",     label: "✅ Hotové" },
];
function workflowGroup(r) {
  if ((r.bucket || "") === "soldout") return "done";   // staré „Hotové" (galočka) ostáva v Hotové
  if (r.refoto) return "new";                            // treba prefotiť → späť do procesu
  if (r.fotoStage === "published") return "done";
  // odfotené (returned) aj čaká na schválenie (approval) → čaká na Mirku
  if (r.fotoStage === "approval" || r.fotoStage === "returned") return "approval";
  if (r.fotoStage === "sent") return "progress";        // odoslané na fotenie = u fotografa
  return "new";                                          // sklad / Bošany / Partizánske
}

/* Stĺpec „Stav fotenia" — rýchly výber koncového stavu.
   Píše sa priamo do fotoStage → synchronizované s Fotením a s etapami vyššie. */
const FOTO_DD = [
  { v: "",          label: "—" },
  { v: "sent",      label: "fotí sa" },
  { v: "approval",  label: "čaká na schválenie" },
  { v: "published", label: "schválené" },
];
const FOTO_DD_VALUES = ["sent", "approval", "published"];
// 'returned' (staré „odfotené") sa v zozname nezobrazuje, ale ak ho niekto nastaví
// vo Fotení (tlačidlo Vrátené), zobrazí sa ako čaká na schválenie.
function fotoDdValue(r) { return r.fotoStage === "returned" ? "approval" : (FOTO_DD_VALUES.includes(r.fotoStage) ? r.fotoStage : ""); }
function fotoDdClass(v) { return v === "published" ? "b-ok" : v === "approval" ? "b-info" : v === "sent" ? "b-warn" : "b-empty"; }
// Etapa fotenia → staré pole photoStatus (kvôli kompatibilite s inými pohľadmi)
function photoStatusForStage(stage) {
  if (stage === "sent") return "Poslané na fotenie";
  if (stage === "returned" || stage === "approval" || stage === "published") return "Vyfotené";
  return "";
}
function fotoDdSelect(r) {
  const cur = fotoDdValue(r);
  const opts = FOTO_DD.map((o) => `<option value="${o.v}" ${o.v === cur ? "selected" : ""}>${o.label}</option>`).join("");
  return `<select class="badge-select foto-dd ${fotoDdClass(cur)}" data-fotodd="${r.id}" title="Stav fotenia">${opts}</select>`;
}

function kovanieClass(v) {
  return v === "Zlaté" ? "b-gold" : v === "Strieborné" ? "b-silver" : "b-empty";
}

function photoStatusClass(v) {
  return v === "Vyfotené" ? "b-ok" : v === "Poslané na fotenie" ? "b-warn" : "b-empty";
}
function statusClass(v) {
  if (v === "Bratislava") return "b-ok";
  if (v === "Partizánske") return "b-blue";
  if (v === "Bošany") return "b-neutral";
  if (v && v.startsWith("V presune")) return "b-warn";
  return "b-empty";
}

// Doplní chýbajúce polia (migrácia starších záznamov v localStorage)
function normalize(rows) {
  return rows.map((r) => {
    const o = {
      photoStatus: "", photoLink: "", transferNo: "",
      transferUp: "", transferDown: "", status: "", rowColor: "", bucket: "",
      webSk: "", webCz: "", kovanie: "", deadline: "", category: "", collection: "",
      fotoNote: "", ...r,
    };
    // Migrácia: starý jeden "transferNo" -> horný presun (na fotenie)
    if (!o.transferUp && o.transferNo) o.transferUp = o.transferNo;
    // Migrácia hodnôt Mesto na nové názvy (Výroba→Bošany, Na ceste→V presune)
    if (STATUS_MIGRATE[o.status]) o.status = STATUS_MIGRATE[o.status];
    return o;
  });
}

/* ---------- Kategórie produktov ----------
   Každý produkt patrí do jednej kategórie:
     "limitka"   -> Limitky (táto stránka)
     "specialka" -> Špeciálka
     "rdf"       -> RDF produkty (pánska línia Raul Del Fuego)
     "nove"      -> Nové produkty
   Nové produkty majú kategóriu uloženú priamo (pole "category").
   Staré dáta bez tohto poľa odhadneme podľa kódu / názvu / poznámky. */
function noDiac(s) {
  return String(s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase();
}
function inferCategory(r) {
  const name = noDiac(r.name), code = noDiac(r.code), note = noDiac(r.note);
  if (name.includes("RDF") || code.includes("RDF") || note.includes("RDF")) return "rdf";
  if (name.includes("SPECIALITKA") || code.includes("SPE") || note.includes("SPEC")) return "specialka";
  if (note.includes("NEW") || note.includes("NOVE") || code.includes("NEW")) return "nove";
  return "limitka";
}
function productCategory(r) { return r.category || inferCategory(r); }

// RDF (Raul Del Fuego) — pánska línia, nepatrí medzi limitky
function isRdfProduct(r) { return productCategory(r) === "rdf"; }

/* Koše (mäkká archivácia riadkov) */
const BUCKETS = [
  { v: "", label: "Pripravuje sa" },
  { v: "mail", label: "Odoslané na mail" },
  { v: "soldout", label: "Hotové" },
  { v: "trash", label: "🗑️ Kôš" },
];
const bucketLabel = (v) => (BUCKETS.find((b) => b.v === v) || {}).label || "";

/* Prednastavené farby riadkov */
const ROW_COLORS = ["", "#efe7f8", "#e3f6ec", "#fdf0dc", "#e2edfb", "#fbe4f0", "#fdecea"];

// Ktorú kategóriu táto stránka zobrazuje. index.html = "limitka",
// specialka.html = "specialka", rdf.html = "rdf", nove.html = "nove".
// Nastavuje sa cez <body data-category="…">.
const PAGE_CATEGORY = document.body.dataset.category || "limitka";

let currentBucket = "new"; // aktívna etapa procesu (alebo "trash" pre Kôš)
let selected = new Set();

// Filter podľa stavu fotenia (klik na počítadlo; "all" = bez filtra)
let fotoFilter = "all";

// Zobrazenie zoznamu: "table" (riadky) alebo "grid" (karty s fotkou)
let viewMode = localStorage.getItem("dr_view_mode") || "table";
function setViewMode(m) {
  viewMode = m;
  try { localStorage.setItem("dr_view_mode", m); } catch (e) {}
  $("#vmGrid")?.classList.toggle("active", m === "grid");
  $("#vmTable")?.classList.toggle("active", m === "table");
  render();
}

let data = load();
let sortKey = "date";
let sortDir = -1; // -1 = desc, 1 = asc
let editingPhoto = "";

/* ---------- Kto naposledy upravil produkt (iniciálky) ----------
   Pred každým uložením sa porovná aktuálny stav so snímkou z posledného
   načítania/uloženia — zmenené produkty dostanú iniciálky prihláseného
   používateľa. Zobrazujú sa ako malý fialový krúžok pri kóde produktu. */
let editSnapshot = {};
function currentUserEmail() {
  try {
    const t = localStorage.getItem("dr_token");
    if (t) {
      const p = JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      if (p.email) return p.email;
    }
  } catch (e) {}
  return localStorage.getItem("dr_email") || "";
}
function userInitials(email) {
  const parts = String(email || "").split("@")[0].split(/[._\-+]/).filter(Boolean);
  if (!parts.length) return "?";
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : parts[0].slice(0, 2)).toUpperCase();
}
function snapOne(r) { const { updatedBy, updatedByEmail, updatedAt, ...rest } = r; return JSON.stringify(rest); }
function takeSnapshot() { editSnapshot = {}; data.forEach((r) => { editSnapshot[r.id] = snapOne(r); }); }
function stampChanges() {
  const email = currentUserEmail();
  if (!email) return;
  const ini = userInitials(email);
  const now = new Date().toISOString();
  data.forEach((r) => {
    const s = snapOne(r);
    if (editSnapshot[r.id] !== s) { r.updatedBy = ini; r.updatedByEmail = email; r.updatedAt = now; editSnapshot[r.id] = s; }
  });
}
function fmtDateTime(iso) {
  const d = new Date(iso);
  return isNaN(d) ? "" : `${d.getDate()}.${d.getMonth() + 1}.${d.getFullYear()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`;
}
function authorChip(r) {
  if (!r.updatedBy) return "";
  const when = r.updatedAt ? " · " + fmtDateTime(r.updatedAt) : "";
  return `<span class="author-chip" title="Naposledy upravil(a): ${esc(r.updatedByEmail || "")}${when}">${esc(r.updatedBy)}</span>`;
}
takeSnapshot();

/* ---------- Storage ---------- */
// Doplní produkty zo zoznamu, ak tam ešte nie sú.
// Zhoda podľa kódu; ak kód chýba, podľa názvu.
function ensureSeed(rows, seedList) {
  let maxId = rows.reduce((m, r) => Math.max(m, r.id || 0), 0);
  seedList.forEach((p) => {
    const exists = p.code
      ? rows.some((r) => r.code === p.code)
      : rows.some((r) => r.name === p.name);
    if (!exists) {
      rows.push({ id: ++maxId, code: p.code || "", name: p.name, photo: "",
        qty: p.qty || 0, place: p.place || "", date: p.date || "2026-07-02",
        desc: p.desc || "", price: p.price || 0, note: p.note || "",
        kovanie: p.kovanie || "", category: p.category || "",
        bucket: p.bucket || "", status: p.status || "" });
    }
  });
}

function load() {
  let rows;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    rows = raw ? JSON.parse(raw) : structuredClone(SEED);
  } catch (e) { rows = structuredClone(SEED); }
  // Jednorazovo doplní RDF a Špecialitky (aj do existujúcich dát v localStorage).
  // Flag zabráni ich opätovnému pridaniu, ak ich používateľ neskôr zmaže.
  if (!localStorage.getItem("dr_rdf_seed_v1")) {
    ensureSeed(rows, RDF_SEED);
    localStorage.setItem("dr_rdf_seed_v1", "1");
  }
  if (!localStorage.getItem("dr_spec_seed_v1")) {
    ensureSeed(rows, SPEC_SEED);
    localStorage.setItem("dr_spec_seed_v1", "1");
  }
  if (!localStorage.getItem("dr_lim_seed_v1")) {
    ensureSeed(rows, LIM_SEED);
    localStorage.setItem("dr_lim_seed_v1", "1");
  }
  // Jednorazovo: odstrániť pánske kozmetické tašky a doplniť pánsku ľadvinku
  if (!localStorage.getItem("dr_rdf_fix_v1")) {
    rows = rows.filter((r) => {
      const n = noDiac(r.name);
      const isMensCosmeticBag = r.code === "PKTRDF9-GM" ||
        (n.includes("PANSK") && n.includes("KOZMETICK") && n.includes("TASK"));
      return !isMensCosmeticBag;
    });
    ensureSeed(rows, RDF_SEED2);
    localStorage.setItem("dr_rdf_fix_v1", "1");
  }
  // Jednorazovo: presunúť vybrané limitky do kategórie Špeciálka
  if (!localStorage.getItem("dr_move_spec_v1")) {
    const toSpec = ["KHLLIM7", "KHLLIM8-Z", "BELLIM4-Z", "LARLIM2-Z"];
    rows.forEach((r) => { if (toSpec.includes(r.code)) r.category = "specialka"; });
    localStorage.setItem("dr_move_spec_v1", "1");
  }
  // Jednorazovo: presunúť ďalšie limitky do kategórie Špeciálka
  if (!localStorage.getItem("dr_move_spec_v2")) {
    const toSpec2 = ["KARILIM2-Z", "LIALIM5-Z", "KHLLIM10-Z", "VIKLIM2-Z", "LARLIM3-Z", "LIALIM6-Z", "VANDLIM1-Z", "LIMLIM3-Z"];
    rows.forEach((r) => { if (toSpec2.includes(r.code)) r.category = "specialka"; });
    localStorage.setItem("dr_move_spec_v2", "1");
  }
  // Jednorazovo: presunúť poslednú dávku limitiek do kategórie Špeciálka
  if (!localStorage.getItem("dr_move_spec_v3")) {
    const toSpec3 = ["KARLIM4-Z", "BELLIM5-Z", "VIVLIM2", "LIMLIM4", "POMLIM4-Z", "VIKLIM3-Z", "MIALIM79-Z", "KRILIM1-Z", "BELLIM6-Z"];
    rows.forEach((r) => { if (toSpec3.includes(r.code)) r.category = "specialka"; });
    localStorage.setItem("dr_move_spec_v3", "1");
  }
  // Jednorazovo: odstrániť pôvodné RDF produkty (na želanie používateľa)
  if (!localStorage.getItem("dr_rdf_clear_v1")) {
    const rmCodes = ["SCCRDRDF9", "CRDRDF9-GM", "LADRDF9"];
    const rmNames = [
      "SLIM CARDHOLDER RAUL DEL FUEGO", "PANSKY OPASOK CASUAL",
      "PANSKY OPASOK ELEGANT", "PANSKY CARDHOLDER", "PANSKA LADVINKA",
    ];
    rows = rows.filter((r) => !rmCodes.includes(r.code) && !rmNames.includes(noDiac(r.name)));
    localStorage.setItem("dr_rdf_clear_v1", "1");
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rows));
  return normalize(rows);
}
function save() {
  try {
    lastLocalChange = Date.now(); // pozastaví auto-obnovu, aby neprepísala čerstvú zmenu
    stampChanges(); // označí zmenené produkty iniciálkami prihláseného používateľa
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    saveToServer(); // spoločná databáza – synchronizácia na pozadí
    return true;
  } catch (err) {
    toast("Pamäť je plná — fotka sa neuložila. Skúste menšiu fotku alebo vymažte staré.");
    return false;
  }
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

function collectionBadge(code) {
  const c = (code || "").toUpperCase();
  if (c.startsWith("MIA"))  return `<span class="coll-badge coll-mia">MIA</span>`;
  if (c.startsWith("LIL"))  return `<span class="coll-badge coll-lil">LIL</span>`;
  if (c.startsWith("MAR"))  return `<span class="coll-badge coll-mar">MAR</span>`;
  if (c.startsWith("KT"))   return `<span class="coll-badge coll-kt">KT</span>`;
  if (c.startsWith("ADR"))  return `<span class="coll-badge coll-adr">ADR</span>`;
  if (c.startsWith("LEA"))  return `<span class="coll-badge coll-lea">LEA</span>`;
  if (c.startsWith("MIC"))  return `<span class="coll-badge coll-mic">MIC</span>`;
  return `<span class="coll-badge coll-other">—</span>`;
}

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
  let rows = data.filter((r) => {
    // Zobraz iba produkty kategórie tejto stránky.
    if (productCategory(r) !== PAGE_CATEGORY) return false;
    // Horné záložky = etapy procesu; Kôš a Archív majú vlastné tlačidlá.
    if (currentBucket === "trash") {
      if ((r.bucket || "") !== "trash") return false;
    } else if (currentBucket === "archive") {
      if (!r.archived || (r.bucket || "") === "trash") return false;
    } else {
      if ((r.bucket || "") === "trash" || r.archived) return false;
      if (workflowGroup(r) !== currentBucket) return false;
    }
    // Filter podľa stavu fotenia (počítadlá nad zoznamom)
    if (fotoFilter !== "all" && (r.fotoStage || "") !== fotoFilter) return false;
    if (q) {
      const hay = `${r.code} ${r.name} ${r.desc} ${r.note} ${r.fotoNote} ${r.place}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  rows.sort((a, b) => {
    // Produkty bez dátumu uverejnenia idú vždy navrch (treba im ešte doplniť dátum).
    if (sortKey === "date") {
      const ae = !String(a.date || "").trim(), be = !String(b.date || "").trim();
      if (ae !== be) return ae ? -1 : 1;
    }
    let av = a[sortKey], bv = b[sortKey];
    if (sortKey === "qty" || sortKey === "price") { av = +av; bv = +bv; }
    else { av = String(av).toLowerCase(); bv = String(bv).toLowerCase(); }
    if (av < bv) return -1 * sortDir;
    if (av > bv) return 1 * sortDir;
    // Pri rovnakej hodnote (napr. prázdny dátum) ukáž najnovšie pridané navrchu.
    return (b.id || 0) - (a.id || 0);
  });
  return rows;
}

/* ---------- Render ---------- */
function render() {
  const rows = getView();
  const grid = $("#gridView");
  const tableWrap = document.querySelector(".table-wrap");

  if (viewMode === "grid" && grid) {
    // Zobrazenie ako karty (ikony s fotkou)
    grid.style.display = "";
    if (tableWrap) tableWrap.style.display = "none";
    grid.innerHTML = rows.length
      ? rows.map(cardHtml).join("")
      : `<div class="empty-state" style="grid-column:1/-1"><h3>Žiadne produkty</h3><p>Pridajte prvý produkt alebo zmeňte filter.</p></div>`;
    bindCardEvents();
  } else {
    if (grid) grid.style.display = "none";
    if (tableWrap) tableWrap.style.display = "";
    const tbody = $("#tbody");
    tbody.innerHTML = rows.map(rowHtml).join("");
    $("#emptyState").style.display = rows.length ? "none" : "block";
    renderFooter(rows);
    renderHeaderArrows();
    bindRowEvents();
  }
  renderTabs();
  renderFotoStats();
  renderCharts();
}

/* ---------- Počítadlá stavu fotenia (rovnaké ako vo Fotení) ---------- */
function renderFotoStats() {
  const el = $("#fotoStats");
  if (!el) return;
  // Počítadlá = jemnejší rozpad podľa fotoStage, cez všetky aktívne (mimo koša)
  const rows = data.filter((r) => productCategory(r) === PAGE_CATEGORY && (r.bucket || "") !== "trash" && !r.archived);
  const cnt = (s) => rows.filter((r) => (r.fotoStage || "") === s).length;
  const blocks = [
    { v: "all",         label: "Všetky",       icon: "",   n: rows.length,       cls: "fs-all" },
    { v: "preparing",   label: "Bošany",       icon: "🏘️", n: cnt("preparing"),   cls: "fs-preparing" },
    { v: "partizanske", label: "Partizánske",  icon: "🏙️", n: cnt("partizanske"), cls: "fs-partizanske" },
    { v: "sent",        label: "U fotografa",  icon: "📤", n: cnt("sent"),        cls: "fs-sent" },
    { v: "returned",    label: "Vrátené",      icon: "📥", n: cnt("returned"),    cls: "fs-returned" },
    { v: "published",   label: "Na webe",      icon: "✅", n: cnt("published"),   cls: "fs-published" },
  ];
  el.innerHTML = blocks.map((b) => `
    <button class="foto-stat ${b.cls}${fotoFilter === b.v ? " active" : ""}" data-fstat="${b.v}">
      <span class="fs-num">${b.n}</span>
      <span class="fs-label">${b.icon ? b.icon + " " : ""}${b.label}</span>
    </button>`).join("");
  el.querySelectorAll("[data-fstat]").forEach((b) => {
    b.addEventListener("click", () => {
      fotoFilter = fotoFilter === b.dataset.fstat ? "all" : b.dataset.fstat;
      render();
    });
  });
}

/* ---------- Zobrazenie: karty (ikony) ---------- */
function cardHtml(r) {
  const ph = photoOf(r);
  const photo = ph
    ? `<img class="p-card-photo" src="${ph}" data-photo="${r.id}" alt="" />`
    : `<div class="p-card-photo empty" data-photo="${r.id}">📷 Pridať foto</div>`;
  return `<div class="p-card" data-id="${r.id}">
    ${photo}
    <div class="p-card-body">
      <div class="p-card-top">
        <span class="p-card-code">${esc(r.code)}</span>
        ${r.status ? `<span class="p-card-badge ${statusClass(r.status)}">${esc(r.status)}</span>` : ""}
      </div>
      <div class="p-card-name">${esc(r.name)}</div>
      <div class="p-card-meta">
        <span>Ks: <span class="qty-badge ${qtyClass(r.qty)}">${r.qty}</span></span>
        ${r.price ? `<span class="price">${esc(r.price)}</span>` : ""}
        ${r.date ? `<span>${fmtDate(r.date)}</span>` : ""}
      </div>
      ${r.desc ? `<div class="p-card-desc">${esc(r.desc)}</div>` : ""}
      <div class="p-card-actions">
        <button class="btn btn-ghost" data-cardedit="${r.id}">✏️ Upraviť</button>
        <label class="p-card-hotove" title="Hotové — presunúť do priečinka Hotové">
          <input type="checkbox" class="hotove-check" data-hotoveid="${r.id}" ${r.bucket === "soldout" ? "checked" : ""} /> Hotové
        </label>
        <button class="icon-btn" data-menu="${r.id}" title="Akcie">&#8943;</button>
      </div>
    </div>
  </div>`;
}

function bindCardEvents() {
  document.querySelectorAll("#gridView [data-photo]").forEach((el) => {
    el.addEventListener("click", () => uploadPhotoFor(+el.dataset.photo));
  });
  document.querySelectorAll("#gridView img.p-card-photo").forEach((el) => {
    el.addEventListener("mouseenter", () => showPhotoZoom(el));
    el.addEventListener("mousemove", positionPhotoZoom);
    el.addEventListener("mouseleave", hidePhotoZoom);
  });
  document.querySelectorAll("#gridView [data-cardedit]").forEach((b) => {
    b.addEventListener("click", () => openModal(+b.dataset.cardedit));
  });
  document.querySelectorAll("#gridView [data-menu]").forEach((b) => {
    b.addEventListener("click", (e) => { e.stopPropagation(); openRowMenu(+b.dataset.menu, b); });
  });
  document.querySelectorAll("#gridView .hotove-check").forEach((c) => {
    c.addEventListener("change", () => {
      const row = data.find((r) => r.id === +c.dataset.hotoveid);
      row.bucket = c.checked ? "soldout" : "";
      save();
      render();
      toast(c.checked ? "Presunuté do Hotové" : "Zrušené Hotové");
    });
  });
}

// Súhrn na konci zoznamu: počet produktov a kusov (sumiek) v aktuálnom výbere
function renderFooter(rows) {
  const tfoot = $("#tfoot");
  if (!tfoot) return;
  if (!rows.length) { tfoot.innerHTML = ""; return; }
  const pieces = rows.reduce((s, r) => s + (+r.qty || 0), 0);
  tfoot.innerHTML = `<tr class="sum-row">
    <td colspan="7" class="sum-label">Spolu v zozname</td>
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

// Iba položky priečinka "Pripravuje sa" pre štatistiky a grafy
// (Hotové a Odoslané na mail sa počítajú vo svojich priečinkoch; RDF sem nepatrí)
const activeRows = () => data.filter((r) => !r.bucket && productCategory(r) === PAGE_CATEGORY);

function renderTabs() {
  // Horné záložky = etapy procesu; Kôš a Archív majú vlastné tlačidlá v toolbare
  const catRows = data.filter((r) => productCategory(r) === PAGE_CATEGORY && (r.bucket || "") !== "trash" && !r.archived);
  $("#viewTabs").innerHTML = WF_STAGES.map((s) => {
    const cnt = catRows.filter((r) => workflowGroup(r) === s.v).length;
    return `<button class="view-tab ${s.v === currentBucket ? "active" : ""}" data-bucket="${s.v}">
      ${s.label}<span class="cnt">${cnt}</span></button>`;
  }).join("");
  document.querySelectorAll("#viewTabs [data-bucket]").forEach((t) => {
    t.addEventListener("click", () => { currentBucket = t.dataset.bucket; render(); });
  });

  // Tlačidlo Archív v toolbare
  const archiveBtn = $("#archiveBtn");
  if (archiveBtn) {
    const arCnt = data.filter((r) => r.archived && r.bucket !== "trash" && productCategory(r) === PAGE_CATEGORY).length;
    archiveBtn.innerHTML = `📁 Archív<span class="cnt">${arCnt}</span>`;
    archiveBtn.classList.toggle("active", currentBucket === "archive");
  }

  // Tlačidlo Kôš v toolbare (za Postup)
  const trashBtn = $("#trashBtn");
  if (trashBtn) {
    const trashCnt = data.filter((r) => r.bucket === "trash" && productCategory(r) === PAGE_CATEGORY).length;
    trashBtn.innerHTML = `🗑️ Kôš<span class="cnt">${trashCnt}</span>`;
    trashBtn.classList.toggle("active", currentBucket === "trash");
  }
}

/* ---------- Charts ---------- */
const CHART_PALETTE = ["#753BBD", "#C1A7E2", "#512D6D", "#9b6fd1", "#d8c6ef", "#6a4a8f", "#b08ed9"];

// Kolekciu odvodíme z prvého slova názvu (Mia, Lily, Michaela, Kozmetická…)
function collectionOf(name) {
  const w = String(name).trim().split(/\s+/)[0] || "Iné";
  return w === "Kozmetická" ? "Taštičky" : w;
}
// Ak je kolekcia zadaná manuálne, použije sa tá; inak sa odvodí z názvu.
function collectionName(r) {
  return (r.collection && r.collection.trim()) || collectionOf(r.name);
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
    { label: "Hotové", value: out, color: "#c0392b" },
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
  renderBars("#barsValue", groupBy(A, (r) => collectionName(r), (r) => (+r.qty || 0) * (+r.price || 0)), (v) => `${v.toLocaleString("sk-SK")} €`);
  // Bars: počet kusov podľa kolekcie
  renderBars("#barsQty", groupBy(A, (r) => collectionName(r), (r) => +r.qty || 0), (v) => `${v} ks`);
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
  return `<select class="badge-select ${classFn(value)}" data-selfield="${field}">${opts}</select>`;
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
  const _photo = photoOf(r);
  const thumb = _photo
    ? `<img class="thumb" src="${_photo}" data-photo="${r.id}" alt="" />`
    : `<div class="thumb empty" data-photo="${r.id}">foto</div>`;
  const style = r.rowColor ? ` style="--row-bg:${r.rowColor}"` : "";
  const flagged = (r.refotoNote && r.refotoNote.trim()) || r.refoto; // komentár k fotke → červený riadok
  const bucketCls = r.bucket === "soldout" ? "hotove-row" : (r.bucket === "trash" ? "bucketed" : "");
  const cls = [bucketCls, selected.has(r.id) ? "selected" : "", flagged ? "foto-flag" : ""].join(" ").trim();
  return `<tr data-id="${r.id}" class="${cls}"${style}>
    <td class="sel-td"><input type="checkbox" class="row-sel" data-sel-id="${r.id}" ${selected.has(r.id) ? "checked" : ""} /></td>
    <td class="code">${esc(r.code)}</td>
    <td class="cell-edit" data-field="name" contenteditable="true">${esc(r.name)}</td>
    <td>${thumb}</td>
    <td>${fotoDdSelect(r)}</td>
    <td>${linkCell(r.id, "photoLink", r.photoLink)}</td>
    <td class="qty-cell">
      <button class="qty-step" data-step="-1" data-id="${r.id}" title="−1">−</button>
      <span class="qty-badge ${qtyClass(r.qty)}" data-qtyedit="${r.id}" contenteditable="true" inputmode="numeric">${r.qty}</span>
      <button class="qty-step" data-step="1" data-id="${r.id}" title="+1">+</button>
    </td>
    <td class="cell-edit" data-field="place" contenteditable="true">${esc(r.place)}</td>
    <td>${kovanieCell(r.id, r.kovanie)}</td>
    <td>${selectHtml("status", r.status, STATUSES, statusClass)}</td>
    <td class="check-td"><input type="checkbox" class="hotove-check" data-hotoveid="${r.id}" ${r.bucket === "soldout" ? "checked" : ""} title="Hotové — presunúť do priečinka Hotové" /></td>
    <td>${linkCell(r.id, "webSk", r.webSk)}</td>
    <td>${linkCell(r.id, "webCz", r.webCz)}</td>
    <td class="date-cell" data-datefield="date" data-id="${r.id}" title="Kliknite pre zmenu dátumu">${fmtDate(r.date)}</td>
    <td class="cell-edit desc-cell" data-field="desc" contenteditable="true">${esc(r.desc)}</td>
    <td class="price cell-edit" data-field="price" contenteditable="true">${esc(r.price)}</td>
    <td class="cell-edit note-cell" data-field="note" contenteditable="true" data-note="${esc(r.note)}">${esc(r.note)}</td>
    <td class="row-actions">
      <button class="icon-btn" data-menu="${r.id}" title="Akcie">&#8943;</button>
    </td>
    <td class="cell-edit note-cell foto-comment-cell" data-field="refotoNote" contenteditable="true" data-ph="komentár k fotke…" title="Komentár k fotke — zvýrazní riadok načerveno">${esc(r.refotoNote)}</td>
  </tr>`;
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
      // Komentár k fotke: prítomný text → červený riadok + príznak „prefotiť" (synced s Fotením)
      if (field === "refotoNote") row.refoto = !!val;
      save();
      toast("Uložené");
      if (field === "photoLink" || field === "refotoNote") render(); // prefarbiť riadok / obnoviť odkaz
    });
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); cell.blur(); }
    });
  });
  document.querySelectorAll("[data-selfield]").forEach((sel) => {
    sel.addEventListener("change", () => {
      const id = +sel.closest("tr").dataset.id;
      const field = sel.dataset.selfield;
      const row = data.find((r) => r.id === id);
      row[field] = sel.value;
      // prefarbiť bejdž podľa novej hodnoty (teraz už len „status")
      sel.className = "badge-select " + statusClass(sel.value);
      save();
      toast("Uložené");
    });
  });
  // Stav fotenia: výber koncového stavu (píše sa do fotoStage → posunie etapu)
  document.querySelectorAll(".foto-dd").forEach((sel) => {
    sel.addEventListener("change", () => {
      const row = data.find((r) => r.id === +sel.dataset.fotodd);
      row.fotoStage = sel.value;                       // "", sent, returned, approval, published
      row.photoStatus = photoStatusForStage(sel.value); // synchronizácia so starým poľom
      if (sel.value) row.refoto = false;               // výber stavu ruší príznak „prefotiť"
      save();
      render();                                        // produkt sa presunie do správnej etapy
      toast("Uložené");
    });
  });
  // Hotové: galočka presunie produkt do priečinka Hotové (a späť)
  document.querySelectorAll(".hotove-check").forEach((c) => {
    c.addEventListener("change", () => {
      const row = data.find((r) => r.id === +c.dataset.hotoveid);
      row.bucket = c.checked ? "soldout" : "";
      save();
      render();
      toast(c.checked ? "Presunuté do Hotové" : "Zrušené Hotové");
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
  // Dátum / deadline: klik na bunku otvorí kalendár priamo v tabuľke
  document.querySelectorAll("td.date-cell").forEach((cell) => {
    cell.addEventListener("click", () => {
      if (cell.querySelector("input")) return; // kalendár je už otvorený
      const row = data.find((r) => r.id === +cell.dataset.id);
      const field = cell.dataset.datefield;
      const inp = document.createElement("input");
      inp.type = "date";
      inp.className = "date-inline";
      inp.value = row[field] || "";
      cell.textContent = "";
      cell.appendChild(inp);
      let finished = false;
      const done = (saveVal) => {
        if (finished) return;
        finished = true;
        if (saveVal && inp.value !== (row[field] || "")) {
          row[field] = inp.value;
          save();
          toast("Uložené");
        }
        render();
      };
      inp.addEventListener("change", () => done(true));
      inp.addEventListener("blur", () => done(true));
      inp.addEventListener("keydown", (e) => {
        if (e.key === "Escape") { e.preventDefault(); done(false); }
      });
      inp.focus();
      try { inp.showPicker?.(); } catch (_) { /* bez user-gesture sa kalendár neotvorí sám */ }
    });
  });
  // Zväčšenie textu pri prejdení myšou (mimo orezania tabuľky)
  document.querySelectorAll("td.note-cell, td.desc-cell").forEach((el) => {
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
  const inTrash = currentBucket === "trash";
  const inArchive = currentBucket === "archive";
  bar.innerHTML = (inTrash || inArchive)
    ? `
    <span class="cnt">${selected.size} vybrané</span>
    <button class="bulk-btn" data-bact="restore">↩️ Obnoviť</button>
    <button class="bulk-btn danger" data-bact="purge">🗑️ Vymazať navždy</button>
    <button class="bulk-btn" data-bact="clear">✕ Zrušiť výber</button>`
    : `
    <span class="cnt">${selected.size} vybrané</span>
    <div class="bulk-swatches">${swatches}</div>
    <button class="bulk-btn" data-bact="soldout">🏷️ Označiť Hotové</button>
    <button class="bulk-btn" data-bact="active">↩️ Zrušiť Hotové</button>
    <button class="bulk-btn" data-bact="archive">📁 Do archívu</button>
    <button class="bulk-btn danger" data-bact="del">🗑️ Do koša</button>
    <button class="bulk-btn" data-bact="clear">✕ Zrušiť výber</button>`;
  bar.classList.add("show");
  bar.querySelectorAll("[data-bcolor]").forEach((sw) =>
    sw.addEventListener("click", () => applyToSelected((r) => (r.rowColor = sw.dataset.bcolor), "Farba zmenená"))
  );
  bar.querySelectorAll("[data-bact]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const act = btn.dataset.bact;
      if (act === "clear") { selected.clear(); render(); return; }
      if (act === "purge") {
        if (!confirm(`Natrvalo vymazať ${selected.size} vybraných produktov? Túto akciu nie je možné vrátiť.`)) return;
        selected.forEach((id) => setPhoto(id, "")); // vymazať aj fotky z IndexedDB
        data = data.filter((r) => !selected.has(r.id));
        selected.clear(); save(); render(); toast("Natrvalo vymazané"); return;
      }
      if (act === "del") {
        applyToSelected((r) => (r.bucket = "trash"), "Presunuté do koša");
        selected.clear(); render(); return;
      }
      if (act === "archive") {
        applyToSelected((r) => { r.archived = true; }, "Presunuté do archívu");
        selected.clear(); render(); return;
      }
      if (act === "restore") {
        applyToSelected((r) => { r.archived = false; r.bucket = ""; }, "Obnovené");
        selected.clear(); render(); return;
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
  const inTrash = row.bucket === "trash";
  const inArchive = !!row.archived && row.bucket !== "trash";
  const bucketItems = [];
  if (inTrash) {
    bucketItems.push(`<button class="rm-item" data-act="restore">↩️ Obnoviť z koša</button>`);
  } else if (inArchive) {
    bucketItems.push(`<button class="rm-item" data-act="restore">↩️ Obnoviť z archívu</button>`);
  } else {
    if (row.bucket !== "soldout") bucketItems.push(`<button class="rm-item" data-act="soldout">🏷️ Označiť Hotové</button>`);
    if (row.bucket === "soldout") bucketItems.push(`<button class="rm-item" data-act="active">↩️ Zrušiť Hotové</button>`);
    bucketItems.push(`<button class="rm-item" data-act="archive">📁 Do archívu</button>`);
  }

  menu.innerHTML = `
    <div class="rm-title">Farba riadku</div>
    <div class="rm-swatches">${swatches}</div>
    <div class="rm-sep"></div>
    ${bucketItems.join("")}
    <div class="rm-sep"></div>
    ${photoOf(row) ? `<button class="rm-item danger" data-act="delphoto">🖼️ Vymazať fotku</button>` : ""}
    <button class="rm-item" data-act="edit">✏️ Upraviť</button>
    <button class="rm-item danger" data-act="del">${(inTrash || inArchive) ? "🗑️ Vymazať navždy" : "🗑️ Do koša"}</button>`;

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
        if (confirm("Naozaj vymazať fotku?")) { setPhoto(id, "").then(() => { render(); toast("Fotka vymazaná"); }); }
      }
      else if (act === "archive") { row.archived = true; save(); render(); toast("Presunuté do archívu"); }
      else if (act === "restore") { row.archived = false; row.bucket = ""; save(); render(); toast("Obnovené"); }
      else if (act === "active") { row.bucket = ""; save(); render(); toast("Zrušené Hotové"); }
      else { row.bucket = act; save(); render(); toast("Presunuté: Hotové"); }
      closeRowMenu();
    });
  });
}
function closeRowMenu() { $("#rowMenu").classList.remove("open"); }
document.addEventListener("click", (e) => {
  if (!e.target.closest("#rowMenu") && !e.target.closest("[data-menu]")) closeRowMenu();
});

/* Zmenší a skomprimuje fotku (JPEG) -> menšia veľkosť pre localStorage.
   Vráti Promise s data URL. max = najdlhšia strana v px. */
function resizeImage(file, max = 1000, quality = 0.72) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        let { width, height } = img;
        if (width > max || height > max) {
          if (width >= height) { height = Math.round(height * max / width); width = max; }
          else { width = Math.round(width * max / height); height = max; }
        }
        const canvas = document.createElement("canvas");
        canvas.width = width; canvas.height = height;
        canvas.getContext("2d").drawImage(img, 0, 0, width, height);
        resolve(canvas.toDataURL("image/jpeg", quality));
      };
      img.onerror = reject;
      img.src = reader.result;
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function uploadPhotoFor(id) {
  const _row = data.find((r) => r.id === id);
  // Ak fotka už existuje, klik ponúkne vymazať (OK) alebo nahradiť novou (Zrušiť)
  if (_row && photoOf(_row)) {
    if (confirm("Vymazať fotku tohto produktu?\n\nOK = vymazať fotku\nZrušiť = nahradiť novou")) {
      setPhoto(id, "").then(() => { render(); toast("Fotka vymazaná"); });
      return;
    }
  }
  const inp = document.createElement("input");
  inp.type = "file"; inp.accept = "image/*";
  inp.onchange = async () => {
    const f = inp.files[0];
    if (!f) return;
    try {
      const dataUrl = await resizeImage(f);
      if (await setPhoto(id, dataUrl)) { render(); toast("Fotka pridaná"); }
    } catch (err) {
      toast("Fotku sa nepodarilo načítať");
    }
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
  if (!row) return;
  if (row.bucket === "trash" || row.archived) {
    // Už je v koši alebo archíve → natrvalo vymazať (bez stopy)
    if (!confirm(`Natrvalo vymazať „${row.name}"? Túto akciu nie je možné vrátiť.`)) return;
    data = data.filter((r) => r.id !== id);
    setPhoto(id, ""); // vymazať aj fotku z IndexedDB
    save(); render(); toast("Natrvalo vymazané");
  } else {
    // Prvé vymazanie → presunúť do koša
    row.bucket = "trash";
    save(); render(); toast("Presunuté do koša");
  }
}

/* ---------- Modal ---------- */
// Naplní datalist existujúcimi názvami kolekcií (na rýchly výber)
function fillCollectionList() {
  const dl = $("#collectionList");
  if (!dl) return;
  const names = [...new Set(data.map((r) => collectionName(r)).filter(Boolean))].sort((a, b) => a.localeCompare(b, "sk"));
  dl.innerHTML = names.map((n) => `<option value="${n}"></option>`).join("");
}

function openModal(id) {
  editingPhoto = "";
  const row = id ? data.find((r) => r.id === id) : null;
  $("#modalTitle").textContent = row ? "Upraviť produkt" : "Nový produkt";
  $("#f-id").value = row ? row.id : "";
  $("#f-category").value = row ? productCategory(row) : PAGE_CATEGORY;
  $("#f-code").value = row ? row.code : "";
  $("#f-name").value = row ? row.name : "";
  if ($("#f-collection")) $("#f-collection").value = row ? (row.collection || "") : "";
  fillCollectionList();
  $("#f-qty").value = row ? row.qty : "";
  $("#f-place").value = row ? row.place : "RRR";
  $("#f-date").value = row ? row.date : new Date().toISOString().slice(0, 10);
  $("#f-desc").value = row ? row.desc : "";
  $("#f-price").value = row ? row.price : "";
  $("#f-note").value = row ? row.note : "";
  if ($("#f-fotoNote")) $("#f-fotoNote").value = row ? (row.fotoNote || "") : "";
  $("#f-status").value = row ? row.status : "";
  $("#f-kovanie").value = row ? row.kovanie : "";
  $("#f-transferUp").value = row ? row.transferUp : "";
  $("#f-transferDown").value = row ? row.transferDown : "";
  $("#f-photoStatus").value = row ? fotoDdValue(row) : "";
  $("#f-photoLink").value = row ? row.photoLink : "";
  $("#f-webSk").value = row ? row.webSk : "";
  $("#f-webCz").value = row ? row.webCz : "";
  $("#f-deadline").value = row ? (row.deadline || "") : "";
  editingPhoto = row ? photoOf(row) : "";
  $("#photoPreview").innerHTML = editingPhoto ? `<img src="${editingPhoto}" />` : "Kliknite pre nahratie fotky";
  $("#photoRemoveBtn").style.display = editingPhoto ? "inline-flex" : "none";
  $("#modalBg").classList.add("open");
}
function closeModal() { $("#modalBg").classList.remove("open"); }

async function saveModal() {
  const id = $("#f-id").value;
  // „Stav fotenia" v okne píše priamo do fotoStage; „—" nezmaže polohu (Bošany…),
  // zruší len koncový stav (odfotené/čaká/schválené).
  const fotoDdSel = $("#f-photoStatus").value;
  const prevRow   = id ? data.find((r) => r.id === +id) : null;
  const prevStage = prevRow ? (prevRow.fotoStage || "") : "";
  const newStage  = fotoDdSel ? fotoDdSel : (FOTO_DD_VALUES.includes(prevStage) ? "" : prevStage);
  const rec = {
    category: $("#f-category").value,
    code: $("#f-code").value.trim(),
    name: $("#f-name").value.trim(),
    collection: $("#f-collection")?.value.trim() || "",
    qty: Math.max(0, parseInt($("#f-qty").value) || 0),
    place: $("#f-place").value.trim(),
    date: $("#f-date").value,
    desc: $("#f-desc").value.trim(),
    price: +$("#f-price").value || 0,
    note: $("#f-note").value.trim(),
    fotoNote: $("#f-fotoNote")?.value.trim() || "",
    status: $("#f-status").value,
    kovanie: $("#f-kovanie").value,
    transferUp: $("#f-transferUp").value.trim(),
    transferDown: $("#f-transferDown").value.trim(),
    fotoStage: newStage,
    photoStatus: photoStatusForStage(newStage),
    photoLink: $("#f-photoLink").value.trim(),
    webSk: $("#f-webSk").value.trim(),
    webCz: $("#f-webCz").value.trim(),
    deadline: $("#f-deadline").value,
    photo: "",
  };
  if (!rec.code || !rec.name) { toast("Vyplňte Kód a Názov"); return; }
  let savedId;
  if (id) {
    savedId = +id;
    Object.assign(data.find((r) => r.id === savedId), rec);
  } else {
    savedId = nextId();
    data.push({ id: savedId, ...rec });
  }
  if (newStage) { const rr = data.find((r) => r.id === savedId); if (rr) rr.refoto = false; }
  if (!save()) return;
  // Fotka ide do IndexedDB (nie do localStorage)
  await setPhoto(savedId, editingPhoto || "");
  closeModal(); render(); toast("Uložené");
}

/* ---------- Export ---------- */
function exportCSV() {
  const cols = ["category", "collection", "code", "name", "qty", "place", "kovanie", "status", "transferUp", "transferDown", "photoStatus", "photoLink", "fotoNote", "webSk", "webCz", "date", "deadline", "desc", "price", "note", "bucket"];
  const head = ["Kategória", "Kolekcia", "Kód", "Názov produktu", "Počet ks", "Miesto výroby", "Kovanie", "Stav", "Presun na fotenie", "Presun na sklad", "Stav fotenia", "Odkaz na fotky", "Poznámka pre fotenie", "Web SK", "Web CZ", "Dátum uverejnenia", "Deadline", "Popis", "Cena", "Poznámka", "Kôš"];
  // Pozn.: stĺpec "Stav" v tabuľke je premenovaný na "Mesto", v CSV ostáva pole `status`.
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
function fillModalSelects() {
  const opt = (o) => `<option value="${esc(o)}">${o || "—"}</option>`;
  $("#f-status").innerHTML = STATUSES.map(opt).join("");
  $("#f-kovanie").innerHTML = KOVANIE.map(opt).join("");
  $("#f-photoStatus").innerHTML = FOTO_DD.map((o) => `<option value="${esc(o.v)}">${o.label}</option>`).join("");
}

document.querySelectorAll("thead th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const k = th.dataset.sort;
    if (sortKey === k) sortDir *= -1; else { sortKey = k; sortDir = 1; }
    render();
  });
});
$("#selAll")?.addEventListener("change", (e) => {
  const ids = getView().map((r) => r.id);
  if (e.target.checked) ids.forEach((id) => selected.add(id));
  else ids.forEach((id) => selected.delete(id));
  render();
  renderBulkBar();
});
$("#searchInput")?.addEventListener("input", render);
$("#vmGrid")?.addEventListener("click", () => setViewMode("grid"));
$("#vmTable")?.addEventListener("click", () => setViewMode("table"));
$("#vmGrid")?.classList.toggle("active", viewMode === "grid");
$("#vmTable")?.classList.toggle("active", viewMode === "table");
$("#addBtn")?.addEventListener("click", () => openModal(null));
$("#exportBtn")?.addEventListener("click", exportCSV);
$("#backupPhotosBtn")?.addEventListener("click", (e) => backupPhotos(e.currentTarget));
$("#trashBtn")?.addEventListener("click", () => { currentBucket = "trash"; render(); });
$("#archiveBtn")?.addEventListener("click", () => { currentBucket = "archive"; render(); });
$("#cancelBtn")?.addEventListener("click", closeModal);
$("#saveBtn")?.addEventListener("click", saveModal);
$("#modalBg")?.addEventListener("click", (e) => { if (e.target.id === "modalBg") closeModal(); });
$("#photoDrop")?.addEventListener("click", () => $("#f-photo").click());
$("#f-photo")?.addEventListener("change", async () => {
  const f = $("#f-photo").files[0];
  if (!f) return;
  try {
    editingPhoto = await resizeImage(f);
    $("#photoPreview").innerHTML = `<img src="${editingPhoto}" />`;
    $("#photoRemoveBtn").style.display = "inline-flex";
  } catch (err) {
    toast("Fotku sa nepodarilo načítať");
  }
});
$("#photoRemoveBtn")?.addEventListener("click", () => {
  editingPhoto = "";
  $("#f-photo").value = "";
  $("#photoPreview").innerHTML = "Kliknite pre nahratie fotky";
  $("#photoRemoveBtn").style.display = "none";
});

fillModalSelects();
render();

/* ── Manuálna šírka stĺpcov (ťahaním hranice v hlavičke, ako v Exceli) ──
   Šírky sa ukladajú do prehliadača (localStorage) samostatne pre každú stránku. */
function initColumnResize() {
  const table = document.querySelector(".table-wrap table");
  if (!table) return;
  const cols = table.querySelectorAll("colgroup col");
  const ths  = table.querySelectorAll("thead th");
  const KEY  = "dr_col_widths_" + PAGE_CATEGORY;
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) {}
  // ak sa zmenil počet stĺpcov, staré šírky zahodíme (nesadli by na správne stĺpce)
  if (saved.__n !== ths.length) saved = {};
  ths.forEach((th, i) => {
    if (!cols[i]) return;
    if (saved[i]) cols[i].style.width = saved[i];
    if (th.querySelector(".col-resizer")) return;
    const rz = document.createElement("div");
    rz.className = "col-resizer";
    rz.title = "Potiahnutím zmeníte šírku stĺpca";
    th.appendChild(rz);
    rz.addEventListener("click", (e) => e.stopPropagation()); // neradiť pri kliknutí na hranicu
    rz.addEventListener("mousedown", (e) => {
      e.preventDefault(); e.stopPropagation();
      const startX = e.clientX;
      const startW = cols[i].getBoundingClientRect().width;
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      const onMove = (ev) => { cols[i].style.width = Math.max(28, startW + ev.clientX - startX) + "px"; };
      const onUp = () => {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        let s = {}; try { s = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) {}
        s[i] = cols[i].style.width; s.__n = ths.length;
        try { localStorage.setItem(KEY, JSON.stringify(s)); } catch (e) {}
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}
initColumnResize();
// Načítať fotky z IndexedDB a presunúť staré fotky z localStorage
(async () => {
  await loadAllPhotos();
  await migratePhotosToIDB(data);
  render();
  await syncFromServer(); // spoločné dáta zo servera (všetky zariadenia)
})();

/* ── Prepínač grafov ── */
(function() {
  const btn    = document.getElementById("chartsToggle");
  const section = document.getElementById("charts");
  if (!btn || !section) return;
  btn.addEventListener("click", () => {
    const open = section.style.display !== "none";
    section.style.display = open ? "none" : "";
    btn.setAttribute("aria-expanded", String(!open));
    btn.querySelector(".charts-toggle-arrow").textContent = open ? "▼" : "▲";
    if (!open) renderCharts();
  });
})();
