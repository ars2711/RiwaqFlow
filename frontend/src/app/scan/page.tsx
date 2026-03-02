"use client";

import { useCallback, useEffect, useMemo, useState, useRef } from "react";
import { Html5QrcodeScanner } from "html5-qrcode";
import {
  CheckCircle,
  XCircle,
  Camera,
  CalendarCheck2,
  ScanLine,
  Fingerprint,
} from "lucide-react";
import { API_BASE } from "@/lib/api";
import { EventItem, ScanResponse } from "@/lib/types";
import BackButton from "@/app/back-button";
import { motion } from "framer-motion";

type QueuedScan = {
  id: string;
  token: string;
  scan_type: "entry" | "exit";
  gate_id: string;
  scanner_id: string;
  queued_at: string;
};

const DB_NAME = "iftar_scanner_db";
const STORE_NAME = "queued_scans";

const openDb = (): Promise<IDBDatabase> =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

const addQueuedScan = async (scan: QueuedScan) => {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(scan);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
};

const getQueuedScans = async (): Promise<QueuedScan[]> => {
  const db = await openDb();
  const result = await new Promise<QueuedScan[]>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => resolve(req.result as QueuedScan[]);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return result;
};

const removeQueuedScan = async (id: string) => {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
};

export default function ScanPage() {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [selectedEventId, setSelectedEventId] = useState("");
  const [scannerCode, setScannerCode] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [scannerToken, setScannerToken] = useState<string | null>(null);
  const [authDisabled, setAuthDisabled] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [scanning, setScanning] = useState(false);

  // Open Database Helper
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const saveScanOffline = async (scanData: unknown) => {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open("Riwaq-offline-scans", 1);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      request.onupgradeneeded = (event: any) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains("scans")) {
          db.createObjectStore("scans", { keyPath: "id", autoIncrement: true });
        }
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      request.onsuccess = (event: any) => {
        const db = event.target.result;
        const tx = db.transaction("scans", "readwrite");
        const store = tx.objectStore("scans");
        store.add(scanData);
        tx.oncomplete = () => {
          // Trigger service worker background sync
          if ("serviceWorker" in navigator && "SyncManager" in window) {
            navigator.serviceWorker.ready
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              .then((swRegistration: any) => {
                return swRegistration.sync.register("sync-scans");
              })
              .catch(() => {});
          }
          resolve(true);
        };
      };
      request.onerror = () => reject(request.error);
    });
  };
  const [scanType, setScanType] = useState<"entry" | "exit">("entry");
  const [queuedCount, setQueuedCount] = useState(0);
  const scannerRef = useRef<Html5QrcodeScanner | null>(null);

  const todaysEvent = useMemo(() => {
    const now = new Date();
    return (
      events.find((event) => {
        const start = new Date(event.starts_at);
        const end = new Date(event.ends_at);
        return start <= now && end >= now;
      }) ?? null
    );
  }, [events]);

  const refreshQueuedCount = useCallback(async () => {
    const queue = await getQueuedScans();
    setQueuedCount(queue.length);
  }, []);

  const syncQueue = useCallback(async () => {
    if (!navigator.onLine || !scannerToken) return;
    const queue = await getQueuedScans();
    for (const queued of queue) {
      const res = await fetch(`${API_BASE}/scan/${queued.scan_type}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${scannerToken}`,
        },
        body: JSON.stringify({
          token: queued.token,
          gate_id: queued.gate_id,
          scanner_id: queued.scanner_id,
        }),
      });
      if (res.ok) {
        await removeQueuedScan(queued.id);
      }
    }
    await refreshQueuedCount();
  }, [refreshQueuedCount, scannerToken]);

  useEffect(() => {
    let storedDeviceId = localStorage.getItem("scanner_device_id");
    if (!storedDeviceId) {
      storedDeviceId = crypto.randomUUID();
      localStorage.setItem("scanner_device_id", storedDeviceId);
    }
    setDeviceId(storedDeviceId);

    const stored = localStorage.getItem("scanner_token");
    if (stored) setScannerToken(stored);
    const storedEvent = localStorage.getItem("scanner_event_id");
    if (storedEvent) setSelectedEventId(storedEvent);

    const loadEvents = async () => {
      try {
        const authRes = await fetch(`${API_BASE}/auth/config`).catch(
          () => null,
        );
        if (authRes?.ok) {
          const payload: { auth_disabled: boolean } = await authRes.json();
          setAuthDisabled(payload.auth_disabled);
          if (payload.auth_disabled) {
            setScannerToken("dev-scanner");
          }
        }

        const res = await fetch(`${API_BASE}/events/`);
        if (!res.ok) return;
        const data: EventItem[] = await res.json();
        setEvents(data);
        if (!storedEvent && data.length > 0) {
          setSelectedEventId(data[0].id);
        }
      } catch {
        /* backend offline – scanner can still scan in offline mode */
      }
    };
    void loadEvents();
  }, []);

  useEffect(() => {
    refreshQueuedCount();
    syncQueue();
    const onOnline = () => {
      syncQueue();
    };
    window.addEventListener("online", onOnline);
    return () => window.removeEventListener("online", onOnline);
  }, [refreshQueuedCount, syncQueue]);

  useEffect(() => {
    if (scanning && !scannerRef.current) {
      scannerRef.current = new Html5QrcodeScanner(
        "reader",
        { fps: 10, qrbox: { width: 250, height: 250 } },
        false,
      );

      scannerRef.current.render(
        async (decodedText) => {
          // Pause scanning
          if (scannerRef.current) {
            scannerRef.current.pause(true);
          }

          try {
            // Extract token from URL if it's a URL, otherwise assume it's the token
            let token = decodedText;
            try {
              const url = new URL(decodedText);
              token = url.searchParams.get("t") || decodedText;
            } catch {
              // Not a URL, use as is
            }

            const verifyRes = await fetch(`${API_BASE}/api/verify`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${scannerToken}`,
              },
              body: JSON.stringify({
                token,
                gate_id: selectedEventId
                  ? `Gate-${selectedEventId.slice(0, 4)}`
                  : "Gate-1",
                scanner_id: "EventScanner",
              }),
            });

            if (!verifyRes.ok) {
              throw new Error("Verification failed");
            }

            const verified: ScanResponse = await verifyRes.json();
            if (verified.status !== "success") {
              setScanResult(verified);
              return;
            }

            const res = await fetch(`${API_BASE}/scan/${scanType}`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${scannerToken}`,
              },
              body: JSON.stringify({
                token,
                gate_id: selectedEventId
                  ? `Gate-${selectedEventId.slice(0, 4)}`
                  : "Gate-1",
                scanner_id: "EventScanner",
              }),
            });

            if (!res.ok) {
              throw new Error("Scan submission failed");
            }

            const data: ScanResponse = await res.json();
            setScanResult(data);
          } catch {
            const queued: QueuedScan = {
              id: crypto.randomUUID(),
              token: (() => {
                try {
                  const url = new URL(decodedText);
                  return url.searchParams.get("t") || decodedText;
                } catch {
                  return decodedText;
                }
              })(),
              scan_type: scanType,
              gate_id: selectedEventId
                ? `Gate-${selectedEventId.slice(0, 4)}`
                : "Gate-1",
              scanner_id: "EventScanner",
              queued_at: new Date().toISOString(),
            };
            await addQueuedScan(queued);
            await refreshQueuedCount();
            setScanResult({
              status: "error",
              message: "Offline queued for sync",
              ticket: null,
            });
          }
        },
        () => {
          // Ignore scan errors (happens when no QR is in frame)
        },
      );
    }

    return () => {
      if (scannerRef.current) {
        scannerRef.current.clear().catch(console.error);
        scannerRef.current = null;
      }
    };
  }, [scanning, scanType, refreshQueuedCount, scannerToken, selectedEventId]);

  const loginScanner = async () => {
    if (!selectedEventId || !scannerCode) {
      alert("Select event and enter scanner code");
      return;
    }
    const res = await fetch(`${API_BASE}/auth/scanner-event-login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event_id: selectedEventId,
        code: scannerCode,
        device_id: deviceId,
      }),
    });
    if (!res.ok) {
      alert("Invalid event scanner code");
      return;
    }
    const payload: { access_token: string } = await res.json();
    localStorage.setItem("scanner_token", payload.access_token);
    localStorage.setItem("scanner_event_id", selectedEventId);
    setScannerToken(payload.access_token);
  };

  if (!scannerToken) {
    return (
      <div className="app-shell flex items-center justify-center p-4 relative overflow-hidden">
        <div className="pulse-orb h-44 w-44 left-[-1.5rem] top-[9rem] bg-blue-500/70" />
        <div className="w-full max-w-sm glass-panel p-8 space-y-4 rounded-3xl relative overflow-hidden border border-[var(--primary)]/20 shadow-[0_0_50px_rgba(59,130,246,0.15)] mt-10">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(59,130,246,0.15),transparent_50%)] pointer-events-none" />

          <BackButton href="/" label="Back" />

          <div className="flex flex-col items-center justify-center pt-2 pb-4 text-center">
            <motion.div className="mb-4 relative flex items-center justify-center w-20 h-20 rounded-full bg-[var(--primary)]/10 ring-1 ring-[var(--primary)]/30">
              <motion.div
                className="absolute inset-1 rounded-full border border-[var(--primary)]/30"
                animate={{ rotate: 360 }}
                transition={{ repeat: Infinity, duration: 4, ease: "linear" }}
                style={{ borderTopColor: "var(--primary)" }}
              />
              <ScanLine className="w-8 h-8 text-[var(--primary)]" />
            </motion.div>
            <h1 className="text-3xl font-black bg-clip-text text-transparent bg-gradient-to-r from-blue-500 to-cyan-400">
              Scanner Access
            </h1>
            <p className="text-sm text-[var(--fg-muted)] mt-2">
              Authorized NUST staff only. Login is event-specific and
              device-controlled.
            </p>
          </div>
          {authDisabled && (
            <p className="text-xs section-subtitle">
              Local mode: auth disabled, scanner login optional.
            </p>
          )}
          {todaysEvent && (
            <button
              type="button"
              className="btn-secondary w-full py-2 text-sm"
              onClick={() => setSelectedEventId(todaysEvent.id)}
            >
              <CalendarCheck2 className="h-4 w-4" />
              Join today&apos;s event: {todaysEvent.name}
            </button>
          )}
          <div className="space-y-3 relative z-10 w-full">
            <select
              title="Event"
              value={selectedEventId}
              onChange={(event) => setSelectedEventId(event.target.value)}
              className="field rounded-xl font-medium"
            >
              <option value="">Select an event to begin</option>
              {events.map((event) => (
                <option key={event.id} value={event.id}>
                  {event.society_name ? `${event.society_name} • ` : ""}
                  {event.name}
                </option>
              ))}
            </select>

            <div className="relative">
              <input
                title="Event scanner code"
                placeholder="Enter scanner secure code"
                type="password"
                value={scannerCode}
                onChange={(event) => setScannerCode(event.target.value)}
                className="field rounded-xl pl-10 tracking-widest font-mono text-sm"
              />
              <Fingerprint className="w-5 h-5 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--fg-muted)]" />
            </div>

            <div className="pt-2 text-center text-[10px] text-[var(--fg-muted)] flex items-center justify-center gap-1.5 opacity-60 bg-[var(--fg)]/5 py-1.5 rounded-md">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Device ID:{" "}
              <span className="font-mono">
                {deviceId ? deviceId.split("-")[0] + "..." : "initializing..."}
              </span>
            </div>

            <button
              onClick={loginScanner}
              className="w-full py-3.5 mt-2 bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-[var(--foreground)] rounded-xl font-bold shadow-lg shadow-blue-500/25 transition-all transform active:scale-95 flex items-center justify-center gap-2"
            >
              Initialize Scanner
            </button>
          </div>
        </div>
      </div>
    );
  }

  const handleNextScan = () => {
    setScanResult(null);
    if (scannerRef.current) {
      scannerRef.current.resume();
    }
  };

  return (
    <div className="app-shell flex flex-col items-center p-4 relative overflow-hidden">
      <div className="pulse-orb h-52 w-52 right-[-2rem] top-[3rem] bg-cyan-400/60" />
      <div className="w-full max-w-md">
        <BackButton href="/" label="Back" />
        <div className="glass-panel p-6 mb-4 text-center">
          <h1 className="text-3xl font-bold">Gate Scanner</h1>
          <p className="text-center text-sm section-subtitle mt-2">
            NUST multi-event verification terminal
          </p>
          <div className="chip mt-3 mx-auto w-fit">
            Queued offline scans: {queuedCount}
          </div>
        </div>

        <p className="text-center text-sm section-subtitle mb-4">
          Queued offline scans: {queuedCount}
        </p>
        <button
          onClick={() => {
            localStorage.removeItem("scanner_token");
            localStorage.removeItem("scanner_event_id");
            setScannerToken(null);
          }}
          className="btn-secondary w-full mb-4 py-2 text-sm"
        >
          Logout Scanner
        </button>

        <div className="glass-soft border border-[var(--border)] flex rounded-lg p-1 mb-6">
          <button
            className={`flex-1 py-3 rounded-md font-bold text-lg transition-colors ${
              scanType === "entry"
                ? "bg-[var(--primary)] text-[var(--foreground)]"
                : "section-subtitle"
            }`}
            onClick={() => setScanType("entry")}
          >
            ENTRY
          </button>
          <button
            className={`flex-1 py-3 rounded-md font-bold text-lg transition-colors ${
              scanType === "exit"
                ? "bg-orange-500 text-[var(--foreground)]"
                : "section-subtitle"
            }`}
            onClick={() => setScanType("exit")}
          >
            EXIT
          </button>
        </div>

        {!scanning ? (
          <button
            onClick={() => setScanning(true)}
            className="btn-primary w-full py-4 rounded-xl font-bold text-xl flex items-center justify-center"
          >
            <Camera className="mr-2" /> Start Scanner
          </button>
        ) : (
          <div className="glass-panel rounded-xl overflow-hidden">
            <div id="reader" className="w-full"></div>
          </div>
        )}

        {scanResult && (
          <div className="fixed inset-0 bg-background/90 flex items-center justify-center p-4 z-50">
            <div
              className={`w-full max-w-sm rounded-2xl p-6 text-center ${
                scanResult.status === "success"
                  ? scanType === "exit"
                    ? "bg-yellow-500"
                    : "bg-green-500"
                  : scanResult.message.toLowerCase().includes("already")
                    ? "bg-yellow-500"
                    : scanResult.message
                          .toLowerCase()
                          .includes("offline queued")
                      ? "bg-orange-500"
                      : "bg-red-500"
              }`}
            >
              {scanResult.status === "success" ? (
                <CheckCircle className="w-24 h-24 mx-auto text-[var(--foreground)] mb-4" />
              ) : (
                <XCircle className="w-24 h-24 mx-auto text-[var(--foreground)] mb-4" />
              )}

              <h2 className="text-3xl font-black text-[var(--foreground)] mb-2">
                {scanResult.status === "success" ? "VALID" : "DENIED"}
              </h2>
              <p className="text-[var(--foreground)]/90 text-lg font-medium mb-6">
                {scanResult.message}
              </p>

              {scanResult.ticket && (
                <div className="bg-[var(--foreground)]/10 rounded-xl p-4 text-left mb-6 text-[var(--foreground)]">
                  <p className="font-bold text-xl">
                    {scanResult.ticket.holder_name}
                  </p>
                  <p className="text-sm opacity-90">
                    {scanResult.ticket.ticket_type} • {scanResult.ticket.role}
                  </p>
                  <div className="mt-2 flex justify-between text-sm font-bold">
                    <span>Entries: {scanResult.ticket.entry_count}</span>
                    <span>Exits: {scanResult.ticket.exit_count}</span>
                  </div>
                </div>
              )}

              <button
                onClick={handleNextScan}
                className="w-full bg-[var(--foreground)] text-[var(--background)] py-4 rounded-xl font-bold text-xl"
              >
                Scan Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
