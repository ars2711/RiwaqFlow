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
          if (scannerRef.current) {
            scannerRef.current.pause(true);
          }

          try {
            let token = decodedText;
            try {
              const url = new URL(decodedText);
              token = url.searchParams.get("t") || decodedText;
            } catch {
              // Not a URL
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
          // Ignore scan errors
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

  const handleNextScan = () => {
    setScanResult(null);
    if (scannerRef.current) {
      scannerRef.current.resume();
    }
  };

  if (!scannerToken) {
    return (
      <div className="app-shell flex items-center justify-center p-4 min-h-screen">
        <div className="w-full max-w-sm block-card p-8 space-y-6 relative border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow)]">
          <BackButton href="/" label="Back" />

          <div className="flex flex-col items-center justify-center pt-2 pb-4 text-center">
            <div className="mb-4 relative flex items-center justify-center w-16 h-16 bg-[var(--surface-2)] border border-[var(--border)]">
              <ScanLine className="w-8 h-8 text-[var(--brass)]" />
            </div>
            <h1 className="text-2xl font-bold font-display text-[var(--text)]">
              Scanner Access
            </h1>
            <p className="text-xs text-[var(--muted)] mt-2 font-sans">
              Authorized NUST staff only. Login is event-specific and device-controlled.
            </p>
          </div>

          {authDisabled && (
            <p className="text-xs font-mono text-[var(--verified)] text-center uppercase tracking-wider">
              ⌐ Local mode: auth optional ¬
            </p>
          )}

          {todaysEvent && (
            <button
              type="button"
              className="btn-secondary w-full py-2.5 text-xs flex items-center justify-center gap-2"
              onClick={() => setSelectedEventId(todaysEvent.id)}
            >
              <CalendarCheck2 className="h-4 w-4" />
              Today&apos;s event: {todaysEvent.name}
            </button>
          )}

          <div className="space-y-4">
            <div>
              <label className="section-label block mb-1">Select Event</label>
              <select
                title="Event"
                value={selectedEventId}
                onChange={(event) => setSelectedEventId(event.target.value)}
                className="select"
              >
                <option value="">Select an event to begin</option>
                {events.map((event) => (
                  <option key={event.id} value={event.id}>
                    {event.society_name ? `${event.society_name} • ` : ""}
                    {event.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="section-label block mb-1">Secure Code</label>
              <div className="relative">
                <input
                  title="Event scanner code"
                  placeholder="Enter scanner secure code"
                  type="password"
                  value={scannerCode}
                  onChange={(event) => setScannerCode(event.target.value)}
                  className="field pl-10 font-mono text-sm"
                />
                <Fingerprint className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
              </div>
            </div>

            <div className="pt-2 text-center text-[10px] text-[var(--muted)] flex items-center justify-center gap-1.5 opacity-80 font-mono">
              Device ID:{" "}
              <span className="font-mono">
                {deviceId ? deviceId.split("-")[0] + "..." : "initializing..."}
              </span>
            </div>

            <button
              onClick={loginScanner}
              className="btn-primary w-full py-3.5 flex items-center justify-center gap-2"
            >
              Initialize Scanner
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell flex flex-col items-center p-4 min-h-screen">
      <div className="w-full max-w-md space-y-6">
        <BackButton href="/" label="Back" />

        <div className="block-card p-6 text-center space-y-3 border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow)]">
          <h1 className="text-3xl font-display font-medium">Gate Scanner</h1>
          <p className="text-xs font-mono text-[var(--muted)] uppercase tracking-wider">
            NUST Multi-Event Verification Terminal
          </p>

          <div className="flex justify-center gap-2">
            <span className="stamp-badge neutral">
              Queued offline scans: {queuedCount}
            </span>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            className={`flex-1 py-3 font-mono font-bold text-sm tracking-wider transition-colors border ${
              scanType === "entry"
                ? "bg-[var(--verified)] text-white border-[var(--verified)]"
                : "bg-transparent text-[var(--text)] border-[var(--border)] hover:border-[var(--verified)]"
            }`}
            onClick={() => setScanType("entry")}
          >
            ENTRY MODE
          </button>
          <button
            className={`flex-1 py-3 font-mono font-bold text-sm tracking-wider transition-colors border ${
              scanType === "exit"
                ? "bg-[var(--alert)] text-white border-[var(--alert)]"
                : "bg-transparent text-[var(--text)] border-[var(--border)] hover:border-[var(--alert)]"
            }`}
            onClick={() => setScanType("exit")}
          >
            EXIT MODE
          </button>
        </div>

        {!scanning ? (
          <button
            onClick={() => setScanning(true)}
            className="btn-primary w-full py-5 text-lg flex items-center justify-center gap-2"
          >
            <Camera className="w-5 h-5" /> Start Scanner Camera
          </button>
        ) : (
          <div className="block-card p-2 relative overflow-hidden border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow)]">
            <div className="absolute top-2 left-2 z-10">
              <span className="tag-live">Active</span>
            </div>
            <div id="reader" className="w-full overflow-hidden"></div>
          </div>
        )}

        <button
          onClick={() => {
            localStorage.removeItem("scanner_token");
            localStorage.removeItem("scanner_event_id");
            setScannerToken(null);
          }}
          className="btn-secondary w-full py-3 flex items-center justify-center gap-2"
        >
          Logout Terminal
        </button>

        {scanResult && (
          <div className="fixed inset-0 bg-[var(--bg)]/90 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <div className="w-full max-w-sm block-card p-6 space-y-6 text-center border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow)]">
              <div>
                {scanResult.status === "success" ? (
                  <span className="stamp-badge verified text-xs font-bold py-3 px-6">
                    <CheckCircle className="w-4 h-4" />
                    {scanType === "exit" ? "EXIT SCANNED" : "ENTRY VERIFIED"}
                  </span>
                ) : (
                  <span className="stamp-badge alert text-xs font-bold py-3 px-6">
                    <XCircle className="w-4 h-4" />
                    ACCESS DENIED
                  </span>
                )}
              </div>

              <h2 className="text-xl font-bold font-display">
                {scanResult.status === "success" ? "Valid Ticket" : "Invalid Ticket"}
              </h2>

              <p className="text-sm text-[var(--muted)] leading-relaxed">
                {scanResult.message}
              </p>

              {scanResult.ticket && (
                <div className="bg-[var(--surface-2)] border border-[var(--border)] p-4 text-left space-y-2">
                  <p className="font-display font-medium text-lg">
                    {scanResult.ticket.holder_name}
                  </p>
                  <div className="font-mono text-xs text-[var(--muted)] space-y-1">
                    <p>Tier: {scanResult.ticket.ticket_type}</p>
                    <p>Role: {scanResult.ticket.role}</p>
                    {scanResult.ticket.seat && <p>Seat: {scanResult.ticket.seat}</p>}
                  </div>
                  <div className="pt-2 border-t border-[var(--border)] flex justify-between font-mono text-xs text-[var(--muted)]">
                    <span>Entries: {scanResult.ticket.entry_count}</span>
                    <span>Exits: {scanResult.ticket.exit_count}</span>
                  </div>
                </div>
              )}

              <button
                onClick={handleNextScan}
                className="btn-primary w-full py-4 text-base"
              >
                Scan Next Ticket
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
