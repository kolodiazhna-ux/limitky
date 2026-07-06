const STORAGE_KEY = "dr_inventory_v2";
const PHOTO_DB = "dr_photos";
const PHOTO_STORE = "photos";

let photoData = "";

/* Zmenší a skomprimuje fotku (JPEG) -> menšia veľkosť. Vráti Promise s data URL. */
function resizeImage(file, max = 1200, quality = 0.82) {
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

/* Fotky ukladáme do IndexedDB (nie do localStorage). */
function idbPutPhoto(id, dataUrl) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(PHOTO_DB, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(PHOTO_STORE)) {
        req.result.createObjectStore(PHOTO_STORE);
      }
    };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction(PHOTO_STORE, "readwrite");
      tx.objectStore(PHOTO_STORE).put(dataUrl, id);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    };
    req.onerror = () => reject(req.error);
  });
}

/* Kategória z URL (?cat=limitka|specialka|rdf|nove) — nastaví výber aj nadpis. */
const CATEGORY_LABELS = {
  limitka:   "Nová limitka",
  specialka: "Nová špecialitka",
  rdf:       "Nový RDF produkt",
  nove:      "Nový produkt",
  kozmetika: "Nová kozmetika",
};
(function initCategory() {
  const cat = new URLSearchParams(location.search).get("cat");
  const valid = Object.keys(CATEGORY_LABELS);
  const chosen = valid.includes(cat) ? cat : "limitka";
  const sel = document.getElementById("f-category");
  if (sel) sel.value = chosen;
  const title = document.getElementById("pageTitle");
  if (title) title.textContent = CATEGORY_LABELS[chosen];
  // Nadpis sa aktualizuje aj keď používateľ zmení kategóriu ručne.
  sel?.addEventListener("change", () => {
    if (title) title.textContent = CATEGORY_LABELS[sel.value] || "Nový produkt";
  });
})();

function load() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
  } catch (e) { return []; }
}
function save(rows) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rows));
}
function nextId(rows) {
  return rows.reduce((m, r) => Math.max(m, r.id || 0), 0) + 1;
}

let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

/* Photo upload */
document.getElementById("photoDrop").addEventListener("click", () =>
  document.getElementById("f-photo").click());

document.getElementById("f-photo").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    photoData = await resizeImage(file);
    const preview = document.getElementById("photoPreview");
    preview.innerHTML = `<img src="${photoData}" style="max-width:100%;max-height:180px;border-radius:6px;" />`;
    document.getElementById("photoRemoveBtn").style.display = "block";
  } catch (err) {
    toast("Fotku sa nepodarilo načítať");
  }
});

document.getElementById("photoRemoveBtn").addEventListener("click", () => {
  photoData = "";
  document.getElementById("photoPreview").textContent = "Kliknite pre nahratie fotky";
  document.getElementById("photoRemoveBtn").style.display = "none";
  document.getElementById("f-photo").value = "";
});

/* Save */
// authFetch je z auth.js (pridá prihlasovací token). Fallback na fetch.
const apiFetch = (url, opts) => (typeof authFetch === "function" ? authFetch : fetch)(url, opts);

document.getElementById("saveBtn").addEventListener("click", async () => {
  const name = document.getElementById("f-name").value.trim();
  if (!name) { toast("Zadajte aspoň názov produktu."); return; }

  // Všetky polia okrem id (id doplníme podľa aktuálnych dát).
  const base = {
    category: document.getElementById("f-category").value,
    code: document.getElementById("f-code").value.trim(),
    name,
    collection: document.getElementById("f-collection")?.value.trim() || "",
    photo: "",
    qty: +document.getElementById("f-qty").value || 0,
    place: document.getElementById("f-place").value.trim(),
    date: document.getElementById("f-date").value || "",
    kovanie: document.getElementById("f-kovanie").value,
    status: document.getElementById("f-status").value,
    transferUp: document.getElementById("f-transferUp").value.trim(),
    transferDown: document.getElementById("f-transferDown").value.trim(),
    photoStatus: document.getElementById("f-photoStatus").value,
    photoLink: document.getElementById("f-photoLink").value.trim(),
    webSk: document.getElementById("f-webSk").value.trim(),
    webCz: document.getElementById("f-webCz").value.trim(),
    deadline: document.getElementById("f-deadline").value,
    desc: document.getElementById("f-desc").value.trim(),
    price: +document.getElementById("f-price").value || 0,
    note: document.getElementById("f-note").value.trim(),
    rowColor: "",
    bucket: "",
  };

  let saved = false;
  let newId = null;

  // 1) Spoločná databáza (server) – aby produkt videli všetky zariadenia.
  //    Načítame aktuálny zoznam zo servera, pridáme nový a uložíme späť.
  try {
    const res = await apiFetch("/api/products");
    if (res.ok) {
      const rows = await res.json();
      newId = rows.reduce((m, r) => Math.max(m, r.id || 0), 0) + 1;
      rows.push({ id: newId, ...base });
      const put = await apiFetch("/api/products", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rows),
      });
      if (put.ok) {
        if (photoData) {
          try {
            await apiFetch(`/api/photos/${newId}`, {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ data: photoData }),
            });
          } catch (e) {}
        }
        // Aktualizujeme aj lokálnu kópiu (rýchle zobrazenie, offline záloha).
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(rows)); } catch (e) {}
        if (photoData) { try { await idbPutPhoto(newId, photoData); } catch (e) {} }
        saved = true;
      }
    }
  } catch (e) { /* server nedostupný → fallback nižšie */ }

  // 2) Fallback: lokálne (offline alebo server nedostupný).
  if (!saved) {
    const rows = load();
    newId = nextId(rows);
    rows.push({ id: newId, ...base });
    try {
      save(rows);
    } catch (err) {
      toast("Pamäť je plná — skúste vymazať staré produkty.");
      return;
    }
    if (photoData) { try { await idbPutPhoto(newId, photoData); } catch (err) {} }
  }

  toast("Produkt uložený!");
  // Presmeruj na stránku podľa kategórie, aby používateľ hneď videl nový produkt.
  const dest = {
    limitka: "./index.html",
    specialka: "./specialka.html",
    rdf: "./rdf.html",
    nove: "./nove.html",
    kozmetika: "./kozmetika.html",
  }[base.category] || "./index.html";
  setTimeout(() => { window.location.href = dest; }, 1000);
});
