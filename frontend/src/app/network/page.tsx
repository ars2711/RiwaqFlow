"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import BackButton from "@/app/back-button";
import { API_BASE } from "@/lib/api";
import { AttendeeProfileItem, SocialConnectionItem } from "@/lib/types";
import {
  Users,
  GraduationCap,
  Building2,
  UserPlus,
  Target,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export default function NetworkPage() {
  const [profiles, setProfiles] = useState<AttendeeProfileItem[]>([]);
  const [connections, setConnections] = useState<SocialConnectionItem[]>([]);
  const [query, setQuery] = useState("");
  const [selfProfileId, setSelfProfileId] = useState("");
  const [profileForm, setProfileForm] = useState({
    display_name: "",
    department: "",
    year: "",
    attendee_type: "student",
    interests: "",
    bio: "",
  });

  const loadProfiles = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE}/social/profiles?query=${encodeURIComponent(query)}`,
      );
      if (!res.ok) return;
      const data: AttendeeProfileItem[] = await res.json();
      setProfiles(data);
    } catch {
      /* backend offline */
    }
  }, [query]);

  const loadConnections = useCallback(async (profileId: string) => {
    if (!profileId) return;
    try {
      const res = await fetch(`${API_BASE}/social/connections/${profileId}`);
      if (!res.ok) return;
      const data: SocialConnectionItem[] = await res.json();
      setConnections(data);
    } catch {
      /* backend offline */
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      void loadProfiles();
    }, 0);
    return () => clearTimeout(timer);
  }, [loadProfiles]);

  useEffect(() => {
    const timer = setTimeout(() => {
      void loadProfiles();
    }, 0);
    return () => clearTimeout(timer);
  }, [query, loadProfiles]);

  useEffect(() => {
    if (!selfProfileId) return;
    const timer = setTimeout(() => {
      void loadConnections(selfProfileId);
    }, 0);
    return () => clearTimeout(timer);
  }, [selfProfileId, loadConnections]);

  const interestTags = useMemo(() => {
    const all = profiles.flatMap((p) =>
      (p.interests ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    );
    const counts = new Map<string, number>();
    for (const tag of all) counts.set(tag, (counts.get(tag) ?? 0) + 1);
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [profiles]);

  const createProfile = async () => {
    const res = await fetch(`${API_BASE}/social/profiles`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(profileForm),
    });
    if (!res.ok) return;
    const profile: AttendeeProfileItem = await res.json();
    setSelfProfileId(profile.id);
    await loadProfiles();
  };

  const connectWith = async (recipientProfileId: string) => {
    if (!selfProfileId) return;
    const res = await fetch(`${API_BASE}/social/connect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        requester_profile_id: selfProfileId,
        recipient_profile_id: recipientProfileId,
      }),
    });
    if (!res.ok) return;
    await loadConnections(selfProfileId);
  };

  const acceptConnection = async (connectionId: string) => {
    const res = await fetch(
      `${API_BASE}/social/connect/${connectionId}/accept`,
      { method: "POST" },
    );
    if (!res.ok) return;
    if (selfProfileId) await loadConnections(selfProfileId);
  };

  return (
    <div className="app-shell p-6">
      <div className="max-w-7xl mx-auto grid lg:grid-cols-3 gap-4">
        <div className="glass-panel p-5 space-y-3">
          <BackButton href="/" label="Back" />
          <h1 className="text-2xl font-bold">NUST Professional Directory</h1>
          <p className="text-sm section-subtitle">
            Build verified campus connections by department, year, and
            interests. No open chat or spam channels.
          </p>
          <input
            className="field"
            placeholder="Display name"
            value={profileForm.display_name}
            onChange={(e) =>
              setProfileForm({ ...profileForm, display_name: e.target.value })
            }
          />
          <input
            className="field"
            placeholder="Department"
            value={profileForm.department}
            onChange={(e) =>
              setProfileForm({ ...profileForm, department: e.target.value })
            }
          />
          <input
            className="field"
            placeholder="Year"
            value={profileForm.year}
            onChange={(e) =>
              setProfileForm({ ...profileForm, year: e.target.value })
            }
          />
          <select
            title="Attendee type"
            className="field"
            value={profileForm.attendee_type}
            onChange={(e) =>
              setProfileForm({ ...profileForm, attendee_type: e.target.value })
            }
          >
            <option value="student">Student</option>
            <option value="alumni">Alumni</option>
            <option value="faculty">Faculty</option>
            <option value="guest">Guest</option>
          </select>
          <input
            className="field"
            placeholder="Interests (comma-separated)"
            value={profileForm.interests}
            onChange={(e) =>
              setProfileForm({ ...profileForm, interests: e.target.value })
            }
          />
          <textarea
            className="textarea"
            placeholder="Bio"
            value={profileForm.bio}
            onChange={(e) =>
              setProfileForm({ ...profileForm, bio: e.target.value })
            }
          />
          <button
            className="btn-primary w-full py-2"
            onClick={() => void createProfile()}
          >
            Create / Update Profile
          </button>
          <div className="text-xs section-subtitle">
            My profile ID: {selfProfileId || "(create profile first)"}
          </div>
        </div>

        <div className="glass-panel p-5 space-y-3">
          <h2 className="text-xl font-bold">Discover</h2>
          <input
            className="field"
            placeholder="Search by name or interests"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="flex flex-wrap gap-2">
            {interestTags.map(([tag, count]) => (
              <span key={tag} className="chip">
                {tag} ({count})
              </span>
            ))}
          </div>
          <div className="space-y-2 max-h-[26rem] overflow-auto">
            <AnimatePresence>
              {profiles.map((profile, _idx) => (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ delay: _idx * 0.05 }}
                  whileHover={{ scale: 1.02 }}
                  key={profile.id}
                  className="glass-soft border border-[var(--border)] rounded-2xl p-4 transition-all hover:bg-[var(--fg)]/5 group"
                >
                  <div className="flex gap-3 items-start">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500/20 to-violet-500/20 border border-blue-500/20 flex items-center justify-center shrink-0">
                      <Users className="w-5 h-5 text-[var(--primary)]" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-bold text-base">
                        {profile.display_name}
                      </p>
                      <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-[var(--fg-muted)]">
                        <span className="flex items-center gap-1">
                          <Building2 className="w-3 h-3" />{" "}
                          {profile.department || "N/A"}
                        </span>
                        <span className="flex items-center gap-1">
                          <GraduationCap className="w-3 h-3" />{" "}
                          {profile.year || "N/A"}
                        </span>
                        <span className="bg-[var(--fg)]/10 px-1.5 py-0.5 rounded capitalize">
                          {profile.attendee_type || "-"}
                        </span>
                      </div>
                      {profile.interests && (
                        <p className="text-xs text-[var(--fg-muted)] mt-2 flex items-center gap-1.5">
                          <Target className="w-3 h-3 text-cyan-500" />
                          <span className="truncate">{profile.interests}</span>
                        </p>
                      )}
                    </div>
                  </div>

                  {profile.id !== selfProfileId && (
                    <button
                      className="mt-3 w-full bg-[var(--primary)]/10 text-[var(--primary)] hover:bg-[var(--primary)]/20 hover:text-[var(--primary)] font-semibold border border-[var(--primary)]/20 py-2 rounded-xl text-xs flex items-center justify-center gap-2 transition-all active:scale-[0.98]"
                      onClick={() => void connectWith(profile.id)}
                    >
                      <UserPlus className="w-4 h-4" />
                      Connect
                    </button>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>

        <div className="glass-panel p-5 space-y-3">
          <h2 className="text-xl font-bold">Connection Requests</h2>
          <p className="text-xs section-subtitle">
            Connections are request-based and professional. Keep your profile
            complete to improve trusted discovery.
          </p>
          <div className="space-y-2 max-h-44 overflow-auto">
            {connections.map((connection) => (
              <div
                key={connection.id}
                className="glass-soft rounded-lg p-2 border border-[var(--border)]"
              >
                <div className="flex items-center justify-between">
                  <p className="text-xs font-semibold">
                    Connection #{connection.id.slice(0, 8)}
                  </p>
                  <span className="chip">{connection.status}</span>
                </div>
                {connection.status === "pending" && (
                  <button
                    className="btn-secondary mt-2 px-2 py-1 text-xs"
                    onClick={() => void acceptConnection(connection.id)}
                  >
                    Accept
                  </button>
                )}
              </div>
            ))}
          </div>
          <div className="glass-soft border border-[var(--border)] rounded-lg p-3">
            <p className="text-xs section-subtitle leading-relaxed">
              Messaging is intentionally disabled to keep Riwaq focused on event
              collaboration, trusted networking, and identity-safe discovery.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
