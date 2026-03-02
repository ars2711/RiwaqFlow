const CACHE_NAME = "riwaqflow-cache-v2";
const OFFLINE_DB_NAME = "riwaqflow-offline-scans";
const OFFLINE_STORE_NAME = "scans";

const urlsToCache = [
  "/",
  "/manifest.ts",
  "/favicon.ico",
  "/map",
  "/scan"
];

// Open IndexedDB for offline background sync
function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(OFFLINE_DB_NAME, 1);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(OFFLINE_STORE_NAME)) {
        db.createObjectStore(OFFLINE_STORE_NAME, { keyPath: "id", autoIncrement: true });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function syncOfflineScans() {
  const db = await openDatabase();
  const tx = db.transaction(OFFLINE_STORE_NAME, "readonly");
  const store = tx.objectStore(OFFLINE_STORE_NAME);
  const scans = await new Promise((resolve) => {
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result);
  });

  if (scans.length === 0) return;

  for (const scan of scans) {
    try {
      const res = await fetch(`http://localhost:8000/tickets/scan_${scan.type}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${scan.scannerToken}`
        },
        body: JSON.stringify({
          token: scan.token,
          gate_id: scan.gateId,
          scanner_id: scan.scannerId
        })
      });
      
      if (res.ok) {
        // Delete from local DB upon success
        const deleteTx = db.transaction(OFFLINE_STORE_NAME, "readwrite");
        deleteTx.objectStore(OFFLINE_STORE_NAME).delete(scan.id);
      }
    } catch (e) {
      console.error("Background sync failed for scan:", scan.id, e);
    }
  }
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(urlsToCache);
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) =>
      Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET" || event.request.url.includes("/api/") || event.request.url.includes("/tickets/")) {
    return;
  }
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request).catch(() => caches.match("/"));
    })
  );
});

self.addEventListener("sync", (event) => {
  if (event.tag === "sync-scans") {
    event.waitUntil(syncOfflineScans());
  }
});
