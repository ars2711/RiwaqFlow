"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Download,
  Filter,
  PlusCircle,
  QrCode,
  ShieldBan,
  ShieldCheck,
  Users,
  Lock,
  KeyRound,
  ShieldAlert,
} from "lucide-react";
import { API_BASE, authHeaders } from "@/lib/api";
import { EventItem, PaymentItem, TicketItem } from "@/lib/types";
import BackButton from "@/app/back-button";

type ScanLog = {
  id: string;
  ticket_id: string;
  scan_type: "entry" | "exit";
  scanned_at: string;
  gate_id: string | null;
  scanner_id: string | null;
};

type ScannerCodeItem = {
  id: string;
  event_id: string;
  label: string | null;
  is_active: string;
  expires_at: string | null;
  created_by: string | null;
  created_at: string;
};

type ScannerDeviceItem = {
  id: string;
  event_id: string;
  device_id: string;
  label: string | null;
  is_active: string;
  created_by: string | null;
  created_at: string;
};

const decodeRoleFromToken = (
  token: string,
): { role: string; uid: string | null } => {
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    return { role: payload.role ?? "manager", uid: payload.uid ?? null };
  } catch {
    return { role: "manager", uid: null };
  }
};

export default function AdminPage() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [otp, setOtp] = useState("");
  const [isAuthed, setIsAuthed] = useState(false);
  const [authDisabled, setAuthDisabled] = useState(false);
  const [actorRole, setActorRole] = useState<
    "super_admin" | "manager" | "admin"
  >("manager");
  const [actorUid, setActorUid] = useState<string | null>(null);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [selectedEventId, setSelectedEventId] = useState("");
  const [stats, setStats] = useState<{
    issued: number;
    entries: number;
    exits: number;
  } | null>(null);

  const [eventForm, setEventForm] = useState({
    name: "NUST Iftar 2026",
    society_name: "NUST Startup Community",
    organizer_type: "society" as "society" | "department" | "individual",
    host_department: "",
    organizer_name: "NUST Event Management Team",
    organizer_email: "events@nust.edu.pk",
    logo_url: "",
    description: "Official event ticketing by NUST startup platform.",
    event_tier: "default" as "early-bird" | "default" | "on-spot",
    capacity: "",
    early_bird_price_pkr: "400",
    default_price_pkr: "600",
    on_spot_price_pkr: "800",
    payment_url: "",
    google_form_url: "",
    external_calendar_url: "",
    venue_lat: "",
    venue_lng: "",
    venue: "Main Hall, NUST H-12 Islamabad",
    starts_at: "2026-03-10T17:00",
    ends_at: "2026-03-10T23:00",
  });

  const [ticketForm, setTicketForm] = useState({
    holder_name: "",
    seat: "",
    department: "",
    year: "",
    attendee_type: "student",
    interests: "",
    role: "Student",
    ticket_type: "Regular",
  });

  const [createdTicket, setCreatedTicket] = useState<TicketItem | null>(null);
  const [eventTickets, setEventTickets] = useState<TicketItem[]>([]);
  const [scanLogs, setScanLogs] = useState<ScanLog[]>([]);
  const [payments, setPayments] = useState<PaymentItem[]>([]);
  const [scannerCodes, setScannerCodes] = useState<ScannerCodeItem[]>([]);
  const [scannerDevices, setScannerDevices] = useState<ScannerDeviceItem[]>([]);
  const [bulkCount, setBulkCount] = useState(10);
  const [scannerCodeLabel, setScannerCodeLabel] = useState("Main Gate OC");
  const [scannerCodeValue, setScannerCodeValue] = useState("");
  const [scannerDeviceLabel, setScannerDeviceLabel] =
    useState("Main Gate Phone");
  const [scannerDeviceId, setScannerDeviceId] = useState("");
  const [csvInput, setCsvInput] = useState(
    "holder_name,seat,department,role,ticket_type\nAli Khan,A-12,CS,Student,Regular",
  );
  const [csvUrlInput, setCsvUrlInput] = useState("");
  const [managerForm, setManagerForm] = useState({
    username: "",
    password: "",
    plan_tier: "starter",
    society_name: "",
  });
  const [grantForm, setGrantForm] = useState({ user_id: "", event_id: "" });
  const [twoFaSecret, setTwoFaSecret] = useState<string | null>(null);
  const [twoFaOtp, setTwoFaOtp] = useState("");
  const [kindFilter, setKindFilter] = useState<
    "all" | "society" | "department" | "individual"
  >("all");
  const [venueFilter, setVenueFilter] = useState("");
  const [tierFilter, setTierFilter] = useState<
    "all" | "early-bird" | "default" | "on-spot"
  >("all");
  const [paymentForm, setPaymentForm] = useState({
    ticket_id: "",
    amount_pkr: "500",
    payer_name: "",
    payer_email: "",
    method: "manual",
  });

  const selectedEvent = useMemo(
    () => events.find((event) => event.id === selectedEventId) ?? null,
    [events, selectedEventId],
  );

  const normalizedType = (
    event: EventItem,
  ): "society" | "department" | "individual" => {
    if (event.organizer_type) return event.organizer_type;
    if ((event.host_department ?? "").trim()) return "department";
    if ((event.society_name ?? "").trim()) return "society";
    return "individual";
  };

  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      const type = normalizedType(event);
      const tier = event.event_tier ?? "default";
      const venueOk = venueFilter
        ? (event.venue ?? "").toLowerCase().includes(venueFilter.toLowerCase())
        : true;
      const kindOk = kindFilter === "all" ? true : type === kindFilter;
      const tierOk = tierFilter === "all" ? true : tier === tierFilter;
      return venueOk && kindOk && tierOk;
    });
  }, [events, kindFilter, tierFilter, venueFilter]);

  const login = async (event: FormEvent) => {
    event.preventDefault();
    let res = await fetch(`${API_BASE}/auth/admin-login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, otp }),
    });

    if (!res.ok) {
      res = await fetch(`${API_BASE}/auth/manager-login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, otp }),
      });
    }

    if (!res.ok) {
      alert("Invalid admin/manager login");
      return;
    }

    const data: { access_token: string } = await res.json();
    localStorage.setItem("admin_token", data.access_token);
    const actor = decodeRoleFromToken(data.access_token);
    setActorRole(actor.role as "super_admin" | "manager" | "admin");
    setActorUid(actor.uid);
    setIsAuthed(true);
  };

  const fetchEvents = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/events/`);
      if (!res.ok) return;
      const data: EventItem[] = await res.json();
      setEvents(data);
      if (data.length > 0 && !selectedEventId) {
        setSelectedEventId(data[0].id);
      }
    } catch {
      /* backend offline */
    }
  }, [selectedEventId]);

  const fetchStats = useCallback(async (eventId: string) => {
    if (!eventId) return;
    const res = await fetch(`${API_BASE}/event/${eventId}/stats`, {
      headers: { ...authHeaders() },
    });
    if (!res.ok) return;
    const data: { issued: number; entries: number; exits: number } =
      await res.json();
    setStats(data);
  }, []);

  const fetchEventTickets = useCallback(async (eventId: string) => {
    if (!eventId) return;
    const res = await fetch(`${API_BASE}/event/${eventId}/tickets`, {
      headers: { ...authHeaders() },
    });
    if (!res.ok) return;
    const data: TicketItem[] = await res.json();
    setEventTickets(data);
  }, []);

  const fetchScanLogs = useCallback(async () => {
    const res = await fetch(`${API_BASE}/scans`, {
      headers: { ...authHeaders() },
    });
    if (!res.ok) return;
    const data: ScanLog[] = await res.json();
    setScanLogs(data);
  }, []);

  const fetchPayments = useCallback(async (eventId: string) => {
    if (!eventId) return;
    const res = await fetch(`${API_BASE}/payments?event_id=${eventId}`, {
      headers: { ...authHeaders() },
    });
    if (!res.ok) return;
    const data: PaymentItem[] = await res.json();
    setPayments(data);
  }, []);

  const fetchScannerCodes = useCallback(async (eventId: string) => {
    if (!eventId) return;
    const res = await fetch(`${API_BASE}/events/${eventId}/scanner-codes`, {
      headers: { ...authHeaders() },
    });
    if (!res.ok) return;
    const data: ScannerCodeItem[] = await res.json();
    setScannerCodes(data);
  }, []);

  const fetchScannerDevices = useCallback(async (eventId: string) => {
    if (!eventId) return;
    const res = await fetch(`${API_BASE}/events/${eventId}/scanner-devices`, {
      headers: { ...authHeaders() },
    });
    if (!res.ok) return;
    const data: ScannerDeviceItem[] = await res.json();
    setScannerDevices(data);
  }, []);

  useEffect(() => {
    const fetchAuthMode = async () => {
      const res = await fetch(`${API_BASE}/auth/config`).catch(() => null);
      if (!res || !res.ok) return;
      const payload: { auth_disabled: boolean } = await res.json();
      setAuthDisabled(payload.auth_disabled);
      if (payload.auth_disabled) {
        setActorRole("super_admin");
        setActorUid(null);
        setIsAuthed(true);
      }
    };
    void fetchAuthMode();

    const token = localStorage.getItem("admin_token");
    if (token) {
      const actor = decodeRoleFromToken(token);
      setTimeout(() => {
        setActorRole(actor.role as "super_admin" | "manager" | "admin");
        setActorUid(actor.uid);
      }, 0);
      setTimeout(() => setIsAuthed(true), 0);
    }
  }, []);

  useEffect(() => {
    if (!isAuthed) return;
    const timer = setTimeout(() => {
      void fetchEvents();
    }, 0);
    return () => clearTimeout(timer);
  }, [isAuthed, fetchEvents]);

  useEffect(() => {
    if (!isAuthed || !selectedEventId) return;
    const starter = setTimeout(() => {
      void fetchStats(selectedEventId);
      void fetchEventTickets(selectedEventId);
      void fetchScanLogs();
      void fetchPayments(selectedEventId);
      void fetchScannerCodes(selectedEventId);
      void fetchScannerDevices(selectedEventId);
    }, 0);
    const timer = setInterval(fetchScanLogs, 5000);
    return () => {
      clearTimeout(starter);
      clearInterval(timer);
    };
  }, [
    isAuthed,
    selectedEventId,
    fetchStats,
    fetchEventTickets,
    fetchScanLogs,
    fetchPayments,
    fetchScannerCodes,
    fetchScannerDevices,
  ]);

  const createEvent = async (event: FormEvent) => {
    event.preventDefault();
    const res = await fetch(`${API_BASE}/events/`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({
        ...eventForm,
        capacity: eventForm.capacity ? Number(eventForm.capacity) : null,
        early_bird_price_pkr: eventForm.early_bird_price_pkr
          ? Number(eventForm.early_bird_price_pkr)
          : null,
        default_price_pkr: eventForm.default_price_pkr
          ? Number(eventForm.default_price_pkr)
          : null,
        on_spot_price_pkr: eventForm.on_spot_price_pkr
          ? Number(eventForm.on_spot_price_pkr)
          : null,
        starts_at: new Date(eventForm.starts_at).toISOString(),
        ends_at: new Date(eventForm.ends_at).toISOString(),
      }),
    });

    if (!res.ok) {
      alert("Failed to create event");
      return;
    }

    await fetchEvents();
  };

  const createTicket = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedEventId) {
      alert("Create or select an event first");
      return;
    }

    const res = await fetch(`${API_BASE}/tickets/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ ...ticketForm, event_id: selectedEventId }),
    });

    if (!res.ok) {
      alert("Failed to create ticket");
      return;
    }

    const data: TicketItem = await res.json();
    setCreatedTicket(data);
    setTicketForm({
      holder_name: "",
      seat: "",
      department: "",
      year: "",
      attendee_type: "student",
      interests: "",
      role: "Student",
      ticket_type: "Regular",
    });
    fetchStats(selectedEventId);
    fetchEventTickets(selectedEventId);
  };

  const bulkGenerate = async () => {
    if (!selectedEventId) return;
    const holders = Array.from({ length: bulkCount }).map((_, index) => ({
      holder_name: `Guest ${index + 1}`,
      seat: null,
      department: "General",
      role: "Guest",
      ticket_type: "Regular",
    }));

    const res = await fetch(`${API_BASE}/tickets/bulk-create`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ event_id: selectedEventId, holders }),
    });

    if (!res.ok) {
      alert("Bulk generate failed");
      return;
    }

    fetchStats(selectedEventId);
    fetchEventTickets(selectedEventId);
  };

  const importCsv = async () => {
    if (!selectedEventId) return;
    const lines = csvInput.trim().split(/\r?\n/).filter(Boolean);
    if (lines.length < 2) {
      alert("CSV needs header + at least one row");
      return;
    }

    const headers = lines[0].split(",").map((header) => header.trim());
    const holders = lines.slice(1).map((line) => {
      const values = line.split(",").map((value) => value.trim());
      const row = Object.fromEntries(
        headers.map((header, index) => [header, values[index] ?? ""]),
      );
      return {
        holder_name: row.holder_name || "Unnamed",
        seat: row.seat || null,
        department: row.department || null,
        role: row.role || "Student",
        ticket_type: row.ticket_type || "Regular",
      };
    });

    const res = await fetch(`${API_BASE}/tickets/bulk-create`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ event_id: selectedEventId, holders }),
    });

    if (!res.ok) {
      alert("CSV import failed");
      return;
    }

    fetchStats(selectedEventId);
    fetchEventTickets(selectedEventId);
  };

  const importCsvFromUrl = async () => {
    if (!csvUrlInput.trim()) {
      alert(
        "Enter a CSV URL (Google Forms sheet CSV export or any public CSV)",
      );
      return;
    }
    const res = await fetch(csvUrlInput.trim());
    if (!res.ok) {
      alert("Failed to fetch CSV URL. Ensure it is publicly accessible.");
      return;
    }
    const text = await res.text();
    setCsvInput(text);
    alert("CSV loaded into editor. Review and click Import CSV.");
  };

  const createPaymentRecord = async () => {
    if (!selectedEventId || !paymentForm.ticket_id) {
      alert("Select an event and ticket first");
      return;
    }
    const res = await fetch(`${API_BASE}/payments/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({
        ticket_id: paymentForm.ticket_id,
        event_id: selectedEventId,
        payer_name: paymentForm.payer_name || null,
        payer_email: paymentForm.payer_email || null,
        amount_pkr: Number(paymentForm.amount_pkr || "0"),
        method: paymentForm.method,
      }),
    });
    if (!res.ok) {
      alert("Failed to create payment");
      return;
    }
    setPaymentForm({
      ...paymentForm,
      ticket_id: "",
      payer_name: "",
      payer_email: "",
    });
    fetchPayments(selectedEventId);
  };

  const updatePaymentStatus = async (
    paymentId: string,
    status: "paid" | "failed" | "refunded",
  ) => {
    const res = await fetch(`${API_BASE}/payments/${paymentId}/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({
        status,
        transaction_ref: `LOCAL-${paymentId.slice(0, 8)}-${status}`,
      }),
    });
    if (!res.ok) {
      alert("Failed to update payment status");
      return;
    }
    if (selectedEventId) fetchPayments(selectedEventId);
  };

  const openCheckout = async (paymentId: string) => {
    const res = await fetch(`${API_BASE}/payments/${paymentId}/checkout`, {
      method: "POST",
      headers: { ...authHeaders() },
    });
    if (!res.ok) {
      alert("Failed to generate checkout link");
      return;
    }
    const payload: { checkout_url: string } = await res.json();
    window.open(payload.checkout_url, "_blank", "noopener,noreferrer");
  };

  const revokeTicket = async (ticketId: string) => {
    const res = await fetch(`${API_BASE}/tickets/${ticketId}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ reason: "manual revoke" }),
    });
    if (res.ok && selectedEventId) fetchEventTickets(selectedEventId);
  };

  const reissueTicket = async (ticket: TicketItem) => {
    const res = await fetch(`${API_BASE}/tickets/${ticket.id}/reissue`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({
        holder_name: ticket.holder_name,
        seat: ticket.seat,
        department: ticket.department,
        role: ticket.role,
        ticket_type: ticket.ticket_type,
      }),
    });
    if (res.ok && selectedEventId) fetchEventTickets(selectedEventId);
  };

  const exportLogs = async () => {
    const res = await fetch(`${API_BASE}/scans/export`, {
      headers: { ...authHeaders() },
    });
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "scans.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const createScannerCode = async () => {
    if (!selectedEventId || !scannerCodeValue) {
      alert("Select event and enter scanner code");
      return;
    }
    const res = await fetch(
      `${API_BASE}/events/${selectedEventId}/scanner-codes`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
          label: scannerCodeLabel,
          code: scannerCodeValue,
        }),
      },
    );
    if (!res.ok) {
      alert("Failed to create scanner code");
      return;
    }
    setScannerCodeValue("");
    fetchScannerCodes(selectedEventId);
  };

  const registerScannerDevice = async () => {
    if (!selectedEventId || !scannerDeviceId) {
      alert("Select event and enter device ID");
      return;
    }
    const res = await fetch(
      `${API_BASE}/events/${selectedEventId}/scanner-devices`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
          device_id: scannerDeviceId,
          label: scannerDeviceLabel,
        }),
      },
    );
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      alert(err?.detail || "Failed to register scanner device");
      return;
    }
    setScannerDeviceId("");
    fetchScannerDevices(selectedEventId);
  };

  const setupManager2FA = async () => {
    const res = await fetch(`${API_BASE}/auth/manager-2fa/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      alert(err?.detail || "2FA setup failed");
      return;
    }
    const data: { secret: string; otpauth_url: string } = await res.json();
    setTwoFaSecret(`${data.secret}\n${data.otpauth_url}`);
  };

  const enableManager2FA = async () => {
    const res = await fetch(`${API_BASE}/auth/manager-2fa/enable`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ otp: twoFaOtp }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      alert(err?.detail || "2FA enable failed");
      return;
    }
    alert("Manager 2FA enabled");
  };

  const createManager = async () => {
    const res = await fetch(`${API_BASE}/admin/users`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(managerForm),
    });
    if (!res.ok) {
      alert("Failed to create manager");
      return;
    }
    alert("Manager created. Grant event access below.");
    setManagerForm({
      username: "",
      password: "",
      plan_tier: "starter",
      society_name: "",
    });
  };

  const grantEventAccess = async () => {
    const res = await fetch(`${API_BASE}/admin/access/grant`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(grantForm),
    });
    if (!res.ok) {
      alert("Grant failed");
      return;
    }
    alert("Access granted");
  };

  const heatmap = useMemo(() => {
    const counts = Array.from({ length: 24 }, (_, hour) => ({
      hour,
      value: 0,
    }));
    for (const log of scanLogs) {
      const hour = new Date(log.scanned_at).getHours();
      counts[hour].value += 1;
    }
    const max = Math.max(1, ...counts.map((item) => item.value));
    return counts.map((item) => ({
      ...item,
      percent: (item.value / max) * 100,
    }));
  }, [scanLogs]);

  if (!isAuthed) {
    return (
      <div className="app-shell flex items-center justify-center min-h-screen relative overflow-hidden bg-[radial-gradient(ellipse_at_top,rgba(220,38,38,0.05),transparent_50%)]">
        <div className="absolute inset-0 pointer-events-none bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-[0.03]" />

        <form
          onSubmit={login}
          className="relative z-10 block-card p-10 w-full max-w-md space-y-6 rounded-3xl border border-red-500/20 shadow-[0_0_50px_rgba(220,38,38,0.08)] bg-[var(--foreground)]/5 backdrop-blur-xl"
        >
          <div className="mb-2">
            <BackButton href="/" label="Back to Home" />
          </div>

          <div className="flex flex-col items-center text-center space-y-2 pb-4">
            <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-2">
              <ShieldAlert className="w-8 h-8 text-red-500" />
            </div>
            <h1 className="text-3xl font-black bg-clip-text text-transparent bg-gradient-to-r from-red-500 to-orange-400">
              Admin Portal
            </h1>
            <p className="text-sm text-[var(--fg-muted)]">
              Operations Control Room. Secure login required.
            </p>
          </div>

          <div className="space-y-4">
            <div className="relative">
              <input
                title="Username"
                placeholder="Username"
                className="field pl-11 rounded-xl bg-[var(--fg)]/5 border-transparent focus:border-red-500/50"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />
              <Users className="w-5 h-5 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--fg-muted)]" />
            </div>

            <div className="relative">
              <input
                title="Password"
                placeholder="Password"
                type="password"
                className="field pl-11 rounded-xl bg-[var(--fg)]/5 border-transparent focus:border-red-500/50"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              <Lock className="w-5 h-5 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--fg-muted)]" />
            </div>

            <div className="relative">
              <input
                title="OTP"
                placeholder="Authenticator OTP"
                className="field pl-11 rounded-xl bg-[var(--fg)]/5 border-transparent focus:border-red-500/50 tracking-widest font-mono font-bold"
                value={otp}
                onChange={(event) => setOtp(event.target.value)}
              />
              <KeyRound className="w-5 h-5 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--fg-muted)]" />
            </div>
          </div>

          <button
            className="w-full py-3.5 bg-gradient-to-r from-red-600 to-rose-500 hover:from-red-500 hover:to-rose-400 text-white rounded-xl font-bold tracking-wide shadow-lg shadow-red-500/25 transition-all transform active:scale-95"
            type="submit"
          >
            Authenticate
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="app-shell admin-theme p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <BackButton href="/" label="Back" />
        <div className="block-card p-4 sm:p-5 flex flex-col sm:flex-row justify-between gap-4 sm:items-center">
          <div>
            <h1 className="text-3xl font-bold">Admin Control Room</h1>
            <p className="text-xs section-subtitle mt-1">
              Role: {actorRole}
              {actorUid ? ` • ID: ${actorUid.slice(0, 8)}...` : ""}
              {authDisabled ? " • Auth disabled (local mode)" : ""}
            </p>
            <p className="text-xs section-subtitle">
              NUST society and department event operations
            </p>
          </div>
          <div className="flex gap-2">
            <button
              className="btn-secondary px-4 py-2 font-medium flex items-center"
              onClick={exportLogs}
            >
              <Download className="w-4 h-4 mr-2" /> Export Logs
            </button>
            <button
              className="btn-secondary px-4 py-2 font-medium"
              onClick={() => {
                localStorage.removeItem("admin_token");
                setActorRole("manager");
                setActorUid(null);
                setIsAuthed(false);
              }}
            >
              Logout
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="space-y-6">
            <div className="block-card p-5">
              <h2 className="font-bold text-lg mb-3">Create Event</h2>
              <form onSubmit={createEvent} className="space-y-2">
                <input
                  title="Event name"
                  placeholder="Event name"
                  className="field"
                  value={eventForm.name}
                  onChange={(event) =>
                    setEventForm({ ...eventForm, name: event.target.value })
                  }
                />
                <input
                  title="Society name"
                  placeholder="Society / Department name"
                  className="field"
                  value={eventForm.society_name}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      society_name: event.target.value,
                    })
                  }
                />
                <select
                  title="Organizer type"
                  className="select"
                  value={eventForm.organizer_type}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      organizer_type: event.target.value as
                        | "society"
                        | "department"
                        | "individual",
                    })
                  }
                >
                  <option value="society">Society-based</option>
                  <option value="department">Department-based</option>
                  <option value="individual">Individual/Lone organizer</option>
                </select>
                <input
                  title="Host department"
                  placeholder="Host department (optional)"
                  className="field"
                  value={eventForm.host_department}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      host_department: event.target.value,
                    })
                  }
                />
                <input
                  title="Organizer name"
                  placeholder="Organizer name"
                  className="field"
                  value={eventForm.organizer_name}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      organizer_name: event.target.value,
                    })
                  }
                />
                <input
                  title="Organizer email"
                  placeholder="Organizer contact email"
                  className="field"
                  value={eventForm.organizer_email}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      organizer_email: event.target.value,
                    })
                  }
                />
                <input
                  title="Logo URL"
                  placeholder="Society logo URL"
                  className="field"
                  value={eventForm.logo_url}
                  onChange={(event) =>
                    setEventForm({ ...eventForm, logo_url: event.target.value })
                  }
                />
                <textarea
                  title="Event description"
                  placeholder="Event description"
                  className="textarea"
                  value={eventForm.description}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      description: event.target.value,
                    })
                  }
                />
                <input
                  title="Venue"
                  placeholder="Venue"
                  className="field"
                  value={eventForm.venue}
                  onChange={(event) =>
                    setEventForm({ ...eventForm, venue: event.target.value })
                  }
                />
                <select
                  title="Event tier"
                  className="select"
                  value={eventForm.event_tier}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      event_tier: event.target.value as
                        | "early-bird"
                        | "default"
                        | "on-spot",
                    })
                  }
                >
                  <option value="early-bird">Early Bird</option>
                  <option value="default">Default</option>
                  <option value="on-spot">On-Spot</option>
                </select>
                <input
                  title="Capacity"
                  type="number"
                  placeholder="Capacity (optional)"
                  className="field"
                  value={eventForm.capacity}
                  onChange={(event) =>
                    setEventForm({ ...eventForm, capacity: event.target.value })
                  }
                />
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                  <input
                    title="Early bird price"
                    type="number"
                    placeholder="Early Bird PKR"
                    className="field"
                    value={eventForm.early_bird_price_pkr}
                    onChange={(event) =>
                      setEventForm({
                        ...eventForm,
                        early_bird_price_pkr: event.target.value,
                      })
                    }
                  />
                  <input
                    title="Default price"
                    type="number"
                    placeholder="Default PKR"
                    className="field"
                    value={eventForm.default_price_pkr}
                    onChange={(event) =>
                      setEventForm({
                        ...eventForm,
                        default_price_pkr: event.target.value,
                      })
                    }
                  />
                  <input
                    title="On-spot price"
                    type="number"
                    placeholder="On-Spot PKR"
                    className="field"
                    value={eventForm.on_spot_price_pkr}
                    onChange={(event) =>
                      setEventForm({
                        ...eventForm,
                        on_spot_price_pkr: event.target.value,
                      })
                    }
                  />
                </div>
                <input
                  title="Payment URL"
                  placeholder="Payment URL (optional)"
                  className="field"
                  value={eventForm.payment_url}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      payment_url: event.target.value,
                    })
                  }
                />
                <input
                  title="Google Form URL"
                  placeholder="Google Form URL (optional)"
                  className="field"
                  value={eventForm.google_form_url}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      google_form_url: event.target.value,
                    })
                  }
                />
                <input
                  title="External calendar URL"
                  placeholder="External calendar URL (optional)"
                  className="field"
                  value={eventForm.external_calendar_url}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      external_calendar_url: event.target.value,
                    })
                  }
                />
                <div className="grid grid-cols-2 gap-2">
                  <input
                    title="Venue latitude"
                    placeholder="Venue lat"
                    className="field"
                    value={eventForm.venue_lat}
                    onChange={(event) =>
                      setEventForm({
                        ...eventForm,
                        venue_lat: event.target.value,
                      })
                    }
                  />
                  <input
                    title="Venue longitude"
                    placeholder="Venue lng"
                    className="field"
                    value={eventForm.venue_lng}
                    onChange={(event) =>
                      setEventForm({
                        ...eventForm,
                        venue_lng: event.target.value,
                      })
                    }
                  />
                </div>
                <input
                  title="Starts at"
                  type="datetime-local"
                  className="field"
                  value={eventForm.starts_at}
                  onChange={(event) =>
                    setEventForm({
                      ...eventForm,
                      starts_at: event.target.value,
                    })
                  }
                />
                <input
                  title="Ends at"
                  type="datetime-local"
                  className="field"
                  value={eventForm.ends_at}
                  onChange={(event) =>
                    setEventForm({ ...eventForm, ends_at: event.target.value })
                  }
                />
                <button className="btn-primary w-full py-2 font-semibold">
                  Save Event
                </button>
              </form>
            </div>

            {actorRole === "super_admin" && (
              <div className="block-card p-5">
                <h2 className="font-bold text-lg mb-3">
                  Society Manager Access
                </h2>
                <div className="space-y-2">
                  <input
                    title="Manager username"
                    placeholder="Manager username"
                    className="w-full border rounded-lg px-3 py-2"
                    value={managerForm.username}
                    onChange={(event) =>
                      setManagerForm({
                        ...managerForm,
                        username: event.target.value,
                      })
                    }
                  />
                  <input
                    title="Manager password"
                    type="password"
                    placeholder="Temporary password"
                    className="w-full border rounded-lg px-3 py-2"
                    value={managerForm.password}
                    onChange={(event) =>
                      setManagerForm({
                        ...managerForm,
                        password: event.target.value,
                      })
                    }
                  />
                  <select
                    title="Plan tier"
                    className="w-full border rounded-lg px-3 py-2"
                    value={managerForm.plan_tier}
                    onChange={(event) =>
                      setManagerForm({
                        ...managerForm,
                        plan_tier: event.target.value,
                      })
                    }
                  >
                    <option value="starter">Starter</option>
                    <option value="pro">Pro</option>
                    <option value="enterprise">Enterprise</option>
                  </select>
                  <input
                    title="Society name"
                    placeholder="Society name"
                    className="w-full border rounded-lg px-3 py-2"
                    value={managerForm.society_name}
                    onChange={(event) =>
                      setManagerForm({
                        ...managerForm,
                        society_name: event.target.value,
                      })
                    }
                  />
                  <button
                    onClick={createManager}
                    className="w-full bg-background/80 text-white rounded-lg py-2 font-semibold"
                  >
                    Create Manager
                  </button>

                  <div className="pt-2 border-t mt-2">
                    <input
                      title="Grant user id"
                      placeholder="User ID"
                      className="w-full border rounded-lg px-3 py-2 mb-2"
                      value={grantForm.user_id}
                      onChange={(event) =>
                        setGrantForm({
                          ...grantForm,
                          user_id: event.target.value,
                        })
                      }
                    />
                    <input
                      title="Grant event id"
                      placeholder="Event ID"
                      className="w-full border rounded-lg px-3 py-2 mb-2"
                      value={grantForm.event_id}
                      onChange={(event) =>
                        setGrantForm({
                          ...grantForm,
                          event_id: event.target.value,
                        })
                      }
                    />
                    <button
                      onClick={grantEventAccess}
                      className="w-full bg-indigo-600 text-white rounded-lg py-2 font-semibold"
                    >
                      Grant Event Access
                    </button>
                  </div>
                </div>
              </div>
            )}

            <div className="block-card p-5">
              <h2 className="font-bold text-lg mb-3">Scanner Access Codes</h2>
              <p className="text-xs text-[var(--foreground)] opacity-70 mb-2">
                Codes are event-specific for parallel NUST events.
              </p>
              <input
                title="Scanner code label"
                placeholder="Label (e.g. Main Gate OC)"
                className="w-full border rounded-lg px-3 py-2 mb-2"
                value={scannerCodeLabel}
                onChange={(event) => setScannerCodeLabel(event.target.value)}
              />
              <input
                title="Scanner code"
                placeholder="Create scanner code"
                className="w-full border rounded-lg px-3 py-2 mb-2"
                value={scannerCodeValue}
                onChange={(event) => setScannerCodeValue(event.target.value)}
              />
              <button
                onClick={createScannerCode}
                className="w-full bg-emerald-600 text-white rounded-lg py-2 font-semibold"
              >
                Create Scanner Code
              </button>
              <div className="mt-3 space-y-2 max-h-32 overflow-auto">
                {scannerCodes.map((code) => (
                  <div key={code.id} className="border rounded-lg p-2 text-xs">
                    <p className="font-semibold">
                      {code.label || "Scanner Code"}
                    </p>
                    <p className="text-[var(--foreground)] opacity-70">
                      Created by: {code.created_by || "-"}
                    </p>
                  </div>
                ))}
              </div>

              <div className="pt-3 mt-3 border-t">
                <h3 className="font-semibold text-sm mb-2">
                  Allowlisted Scanner Devices
                </h3>
                <input
                  title="Scanner device label"
                  placeholder="Device label"
                  className="w-full border rounded-lg px-3 py-2 mb-2"
                  value={scannerDeviceLabel}
                  onChange={(event) =>
                    setScannerDeviceLabel(event.target.value)
                  }
                />
                <input
                  title="Scanner device id"
                  placeholder="Device ID from scanner login screen"
                  className="w-full border rounded-lg px-3 py-2 mb-2"
                  value={scannerDeviceId}
                  onChange={(event) => setScannerDeviceId(event.target.value)}
                />
                <button
                  onClick={registerScannerDevice}
                  className="w-full bg-sky-600 text-white rounded-lg py-2 font-semibold"
                >
                  Register Device
                </button>
                <div className="mt-2 space-y-1 max-h-24 overflow-auto">
                  {scannerDevices.map((device) => (
                    <div
                      key={device.id}
                      className="text-[10px] border rounded p-2"
                    >
                      <p className="font-semibold">
                        {device.label || "Scanner Device"}
                      </p>
                      <p className="text-[var(--foreground)] opacity-70 break-all">
                        {device.device_id}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {actorRole === "manager" && (
              <div className="block-card p-5">
                <h2 className="font-bold text-lg mb-3">Manager 2FA</h2>
                <button
                  onClick={setupManager2FA}
                  className="w-full bg-background/80 text-white rounded-lg py-2 font-semibold mb-2"
                >
                  Setup Authenticator
                </button>
                {twoFaSecret && (
                  <textarea
                    title="2FA setup details"
                    readOnly
                    className="w-full border rounded-lg px-3 py-2 text-xs h-20 mb-2"
                    value={twoFaSecret}
                  />
                )}
                <input
                  title="2FA OTP"
                  placeholder="Enter OTP to enable"
                  className="w-full border rounded-lg px-3 py-2 mb-2"
                  value={twoFaOtp}
                  onChange={(event) => setTwoFaOtp(event.target.value)}
                />
                <button
                  onClick={enableManager2FA}
                  className="w-full bg-emerald-600 text-white rounded-lg py-2 font-semibold"
                >
                  Enable 2FA
                </button>
              </div>
            )}

            <div className="block-card p-5">
              <h2 className="font-bold text-lg mb-3 flex items-center">
                <Filter className="w-4 h-4 mr-2" />
                Event Filters
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mb-3">
                <select
                  title="Filter by organizer type"
                  className="select"
                  value={kindFilter}
                  onChange={(event) =>
                    setKindFilter(
                      event.target.value as
                        | "all"
                        | "society"
                        | "department"
                        | "individual",
                    )
                  }
                >
                  <option value="all">All organizer types</option>
                  <option value="society">Society</option>
                  <option value="department">Department</option>
                  <option value="individual">Individual</option>
                </select>
                <select
                  title="Filter by tier"
                  className="select"
                  value={tierFilter}
                  onChange={(event) =>
                    setTierFilter(
                      event.target.value as
                        | "all"
                        | "early-bird"
                        | "default"
                        | "on-spot",
                    )
                  }
                >
                  <option value="all">All tiers</option>
                  <option value="early-bird">Early Bird</option>
                  <option value="default">Default</option>
                  <option value="on-spot">On-Spot</option>
                </select>
                <input
                  title="Filter by venue"
                  className="field"
                  placeholder="Search venue"
                  value={venueFilter}
                  onChange={(event) => setVenueFilter(event.target.value)}
                />
              </div>
              <select
                title="Event"
                className="w-full border rounded-lg px-3 py-2"
                value={selectedEventId}
                onChange={(event) => setSelectedEventId(event.target.value)}
              >
                <option value="">Select event</option>
                {filteredEvents.map((event) => (
                  <option value={event.id} key={event.id}>
                    [{normalizedType(event)}]{" "}
                    {event.society_name ? `${event.society_name} • ` : ""}
                    {event.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="block-card p-5">
              <h2 className="font-bold text-lg mb-3 flex items-center">
                <PlusCircle className="w-4 h-4 mr-2" />
                Create Ticket
              </h2>
              <form onSubmit={createTicket} className="space-y-2">
                <select
                  title="Event"
                  className="w-full border rounded-lg px-3 py-2"
                  value={selectedEventId}
                  onChange={(event) => setSelectedEventId(event.target.value)}
                >
                  <option value="">Select event</option>
                  {filteredEvents.map((event) => (
                    <option value={event.id} key={event.id}>
                      {event.society_name ? `${event.society_name} • ` : ""}
                      {event.name}
                    </option>
                  ))}
                </select>
                <input
                  title="Holder Name"
                  placeholder="Holder Name"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.holder_name}
                  onChange={(event) =>
                    setTicketForm({
                      ...ticketForm,
                      holder_name: event.target.value,
                    })
                  }
                  required
                />
                <input
                  title="Seat"
                  placeholder="Seat (optional)"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.seat}
                  onChange={(event) =>
                    setTicketForm({ ...ticketForm, seat: event.target.value })
                  }
                />
                <input
                  title="Department"
                  placeholder="Department"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.department}
                  onChange={(event) =>
                    setTicketForm({
                      ...ticketForm,
                      department: event.target.value,
                    })
                  }
                />
                <input
                  title="Year"
                  placeholder="Year (e.g. 1st, 2nd, Alumni)"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.year}
                  onChange={(event) =>
                    setTicketForm({
                      ...ticketForm,
                      year: event.target.value,
                    })
                  }
                />
                <select
                  title="Attendee type"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.attendee_type}
                  onChange={(event) =>
                    setTicketForm({
                      ...ticketForm,
                      attendee_type: event.target.value,
                    })
                  }
                >
                  <option value="student">Student</option>
                  <option value="alumni">Alumni</option>
                  <option value="faculty">Faculty</option>
                  <option value="guest">Guest</option>
                </select>
                <input
                  title="Interests"
                  placeholder="Interests (comma-separated)"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.interests}
                  onChange={(event) =>
                    setTicketForm({
                      ...ticketForm,
                      interests: event.target.value,
                    })
                  }
                />
                <select
                  title="Role"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.role}
                  onChange={(event) =>
                    setTicketForm({ ...ticketForm, role: event.target.value })
                  }
                >
                  <option>Student</option>
                  <option>Faculty</option>
                  <option>Guest</option>
                  <option>Staff</option>
                </select>
                <select
                  title="Ticket Type"
                  className="w-full border rounded-lg px-3 py-2"
                  value={ticketForm.ticket_type}
                  onChange={(event) =>
                    setTicketForm({
                      ...ticketForm,
                      ticket_type: event.target.value,
                    })
                  }
                >
                  <option>Regular</option>
                  <option>Early Bird</option>
                  <option>VIP</option>
                  <option>Guest</option>
                  <option>On-Spot</option>
                  <option>OC</option>
                </select>
                <button className="w-full bg-blue-600 text-white rounded-lg py-2 font-semibold">
                  Generate Ticket
                </button>
              </form>
            </div>

            <div className="block-card p-5">
              <h2 className="font-bold text-lg mb-3">Bulk + CSV</h2>
              <div className="flex gap-2 mb-2">
                <input
                  title="Bulk count"
                  type="number"
                  min={1}
                  className="w-full border rounded-lg px-3 py-2"
                  value={bulkCount}
                  onChange={(event) => setBulkCount(Number(event.target.value))}
                />
                <button
                  onClick={bulkGenerate}
                  className="bg-background/80 text-white rounded-lg px-3"
                >
                  Generate
                </button>
              </div>
              <textarea
                title="CSV"
                className="w-full border rounded-lg px-3 py-2 h-32 text-xs"
                value={csvInput}
                onChange={(event) => setCsvInput(event.target.value)}
              />
              <div className="flex gap-2 mt-2">
                <input
                  title="CSV URL"
                  className="field"
                  placeholder="Google Forms/Sheet CSV URL"
                  value={csvUrlInput}
                  onChange={(event) => setCsvUrlInput(event.target.value)}
                />
                <button
                  onClick={importCsvFromUrl}
                  className="btn-secondary px-3"
                >
                  Load URL
                </button>
              </div>
              <button
                onClick={importCsv}
                className="mt-2 w-full bg-indigo-600 text-white rounded-lg py-2 font-semibold"
              >
                Import CSV
              </button>
            </div>
          </div>

          <div className="xl:col-span-2 space-y-6">
            {createdTicket && (
              <div className="block-card p-5">
                <h3 className="text-green-800 font-bold mb-2 flex items-center">
                  <QrCode className="w-5 h-5 mr-2" /> Ticket Created
                </h3>
                <div className="glass-soft p-4 rounded-lg border border-[var(--border)] flex justify-between items-center">
                  <div>
                    <p className="font-bold text-[var(--foreground)] opacity-70">
                      {createdTicket.holder_name}
                    </p>
                    <p className="text-sm text-[var(--foreground)] opacity-70">
                      {createdTicket.ticket_type} • {createdTicket.role} • Seat{" "}
                      {createdTicket.seat || "-"}
                    </p>
                  </div>
                  <a
                    href={`/ticket/${createdTicket.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-blue-600 font-medium text-sm bg-blue-50 px-3 py-1 rounded-full"
                  >
                    Open Ticket ↗
                  </a>
                </div>
              </div>
            )}

            <div className="block-card p-5">
              <h2 className="text-xl font-bold mb-4 flex items-center">
                <Users className="w-5 h-5 mr-2 text-blue-600" /> Stats{" "}
                {selectedEvent ? `• ${selectedEvent.name}` : ""}
              </h2>
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-[var(--foreground)]/5 p-4 rounded-xl border border-white/10">
                  <p className="text-sm text-[var(--foreground)] opacity-70">
                    Issued
                  </p>
                  <p className="text-3xl font-black">{stats?.issued ?? 0}</p>
                </div>
                <div className="bg-blue-50 p-4 rounded-xl border border-blue-100">
                  <p className="text-sm text-blue-700">Entries</p>
                  <p className="text-3xl font-black text-blue-900">
                    {stats?.entries ?? 0}
                  </p>
                </div>
                <div className="bg-orange-50 p-4 rounded-xl border border-orange-100">
                  <p className="text-sm text-orange-700">Exits</p>
                  <p className="text-3xl font-black text-orange-900">
                    {stats?.exits ?? 0}
                  </p>
                </div>
              </div>
            </div>

            <div className="block-card p-5">
              <h2 className="text-xl font-bold mb-4">Entry Heatmap (Hourly)</h2>
              <div className="grid grid-cols-12 gap-2">
                {heatmap.map((item) => {
                  const levelClass =
                    item.percent > 85
                      ? "h-20"
                      : item.percent > 65
                        ? "h-16"
                        : item.percent > 45
                          ? "h-12"
                          : item.percent > 25
                            ? "h-8"
                            : "h-4";

                  return (
                    <div key={item.hour} className="flex flex-col items-center">
                      <div
                        className={`w-full bg-indigo-100 rounded ${levelClass}`}
                      />
                      <span className="text-[10px] text-[var(--foreground)] opacity-70 mt-1">
                        {item.hour}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="block-card p-5">
              <h2 className="text-xl font-bold mb-4">
                Tickets ({eventTickets.length})
              </h2>
              <div className="space-y-2 max-h-72 overflow-auto">
                {eventTickets.map((ticket) => (
                  <div
                    key={ticket.id}
                    className="border rounded-lg p-3 flex justify-between items-center"
                  >
                    <div>
                      <p className="font-semibold text-[var(--foreground)] opacity-70">
                        {ticket.holder_name}
                      </p>
                      <p className="text-xs text-[var(--foreground)] opacity-70">
                        {ticket.ticket_type} • Seat {ticket.seat || "-"} •{" "}
                        {ticket.status}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => revokeTicket(ticket.id)}
                        className="px-2 py-1 text-xs rounded bg-red-50 text-red-700 border border-red-200 flex items-center"
                      >
                        <ShieldBan className="w-3 h-3 mr-1" />
                        Revoke
                      </button>
                      <button
                        onClick={() => reissueTicket(ticket)}
                        className="px-2 py-1 text-xs rounded bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center"
                      >
                        <ShieldCheck className="w-3 h-3 mr-1" />
                        Reissue
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="block-card p-5">
              <h2 className="text-xl font-bold mb-4">
                Payments (Event Scoped)
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-5 gap-2 mb-3">
                <select
                  title="Payment ticket"
                  className="field md:col-span-2"
                  value={paymentForm.ticket_id}
                  onChange={(event) =>
                    setPaymentForm({
                      ...paymentForm,
                      ticket_id: event.target.value,
                    })
                  }
                >
                  <option value="">Select ticket</option>
                  {eventTickets.map((ticket) => (
                    <option key={ticket.id} value={ticket.id}>
                      {ticket.holder_name} • {ticket.ticket_type}
                    </option>
                  ))}
                </select>
                <input
                  title="Amount pkr"
                  className="field"
                  placeholder="Amount PKR"
                  value={paymentForm.amount_pkr}
                  onChange={(event) =>
                    setPaymentForm({
                      ...paymentForm,
                      amount_pkr: event.target.value,
                    })
                  }
                />
                <select
                  title="Payment method"
                  className="field"
                  value={paymentForm.method}
                  onChange={(event) =>
                    setPaymentForm({
                      ...paymentForm,
                      method: event.target.value,
                    })
                  }
                >
                  <option value="manual">Manual</option>
                  <option value="easypaisa">Easypaisa</option>
                  <option value="jazzcash">JazzCash</option>
                  <option value="card">Card</option>
                </select>
                <button onClick={createPaymentRecord} className="btn-primary">
                  Create
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-3">
                <input
                  title="Payer name"
                  className="field"
                  placeholder="Payer name"
                  value={paymentForm.payer_name}
                  onChange={(event) =>
                    setPaymentForm({
                      ...paymentForm,
                      payer_name: event.target.value,
                    })
                  }
                />
                <input
                  title="Payer email"
                  className="field"
                  placeholder="Payer email"
                  value={paymentForm.payer_email}
                  onChange={(event) =>
                    setPaymentForm({
                      ...paymentForm,
                      payer_email: event.target.value,
                    })
                  }
                />
              </div>
              <div className="space-y-2 max-h-64 overflow-auto">
                {payments.map((payment) => (
                  <div
                    key={payment.id}
                    className="border rounded-lg p-3 text-sm"
                  >
                    <div className="flex items-center justify-between">
                      <p className="font-semibold">
                        PKR {payment.amount_pkr} • {payment.method}
                      </p>
                      <span className="chip">{payment.status}</span>
                    </div>
                    <p className="text-xs section-subtitle">
                      Ticket: {payment.ticket_id.slice(0, 8)}... •{" "}
                      {payment.payer_name || "-"}
                    </p>
                    <div className="flex gap-2 mt-2">
                      <button
                        className="btn-secondary px-2 py-1 text-xs"
                        onClick={() => openCheckout(payment.id)}
                      >
                        Checkout
                      </button>
                      <button
                        className="btn-secondary px-2 py-1 text-xs"
                        onClick={() => updatePaymentStatus(payment.id, "paid")}
                      >
                        Mark Paid
                      </button>
                      <button
                        className="btn-secondary px-2 py-1 text-xs"
                        onClick={() =>
                          updatePaymentStatus(payment.id, "failed")
                        }
                      >
                        Mark Failed
                      </button>
                      <button
                        className="btn-secondary px-2 py-1 text-xs"
                        onClick={() =>
                          updatePaymentStatus(payment.id, "refunded")
                        }
                      >
                        Refund
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="block-card p-5">
              <h2 className="text-xl font-bold mb-4">Live Scan Feed</h2>
              <div className="space-y-2 max-h-72 overflow-auto">
                {scanLogs.map((log) => (
                  <div
                    key={log.id}
                    className="border rounded-lg p-3 text-sm flex justify-between"
                  >
                    <span className="font-medium">
                      {log.scan_type.toUpperCase()}
                    </span>
                    <span className="text-[var(--foreground)] opacity-70">
                      {new Date(log.scanned_at).toLocaleString()}
                    </span>
                    <span className="text-[var(--foreground)] opacity-70">
                      {log.gate_id || "Gate"}
                    </span>
                    <span className="text-[var(--foreground)] opacity-70">
                      {log.ticket_id.slice(0, 8)}...
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
