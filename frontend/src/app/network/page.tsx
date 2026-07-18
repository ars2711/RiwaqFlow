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
    const timer = setTimeout(() => { void loadProfiles(); }, 0);
    return () => clearTimeout(timer);
  }, [loadProfiles]);

  useEffect(() => {
    const timer = setTimeout(() => { void loadProfiles(); }, 0);
    return () => clearTimeout(timer);
  }, [query, loadProfiles]);

  useEffect(() => {
    if (!selfProfileId) return;
    const timer = setTimeout(() => { void loadConnections(selfProfileId); }, 0);
    return () => clearTimeout(timer);
  }, [selfProfileId, loadConnections]);

  const interestTags = useMemo(() => {
    const all = profiles.flatMap((p) =>
      (p.interests ?? "").split(",").map((s) => s.trim()).filter(Boolean),
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
    <div className="app-shell">
      <div className="wrap py-10">
        <BackButton href="/" label="Back to Home" />

        <div className="my-8">
          <div className="eyebrow">
            <span className="line"></span> Networking
          </div>
          <h1 className="section-title">Professional Directory</h1>
          <p className="section-subtitle mt-4 max-w-2xl">
            Build verified campus connections by department, year, and interests.
            No open chat or spam channels.
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Profile Form */}
          <div className="bg-[var(--surface)] border border-[var(--border)] p-6 space-y-4 h-fit">
            <h2 className="text-lg font-display font-medium">Your Profile</h2>
            <input
              className="field text-sm"
              placeholder="Display name"
              value={profileForm.display_name}
              onChange={(e) => setProfileForm({ ...profileForm, display_name: e.target.value })}
            />
            <input
              className="field text-sm"
              placeholder="Department"
              value={profileForm.department}
              onChange={(e) => setProfileForm({ ...profileForm, department: e.target.value })}
            />
            <input
              className="field text-sm"
              placeholder="Year"
              value={profileForm.year}
              onChange={(e) => setProfileForm({ ...profileForm, year: e.target.value })}
            />
            <select
              title="Attendee type"
              className="select text-sm"
              value={profileForm.attendee_type}
              onChange={(e) => setProfileForm({ ...profileForm, attendee_type: e.target.value })}
            >
              <option value="student">Student</option>
              <option value="alumni">Alumni</option>
              <option value="faculty">Faculty</option>
              <option value="guest">Guest</option>
            </select>
            <input
              className="field text-sm"
              placeholder="Interests (comma-separated)"
              value={profileForm.interests}
              onChange={(e) => setProfileForm({ ...profileForm, interests: e.target.value })}
            />
            <textarea
              className="textarea text-sm"
              placeholder="Bio"
              rows={3}
              value={profileForm.bio}
              onChange={(e) => setProfileForm({ ...profileForm, bio: e.target.value })}
            />
            <button
              className="btn-primary w-full"
              onClick={() => void createProfile()}
            >
              Create / Update
            </button>
            <div className="text-[10px] font-mono text-[var(--muted)] pt-2 uppercase tracking-widest text-center">
              ID: {selfProfileId || "PENDING_CREATE"}
            </div>
          </div>

          {/* Directory */}
          <div className="bg-[var(--surface)] border border-[var(--border)] p-6 flex flex-col gap-4">
            <h2 className="text-lg font-display font-medium">Discover</h2>
            <input
              className="field text-sm"
              placeholder="Search by name or interests"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <div className="flex flex-wrap gap-2">
              {interestTags.map(([tag, count]) => (
                <span key={tag} className="text-[10px] font-mono border border-[var(--border)] px-2 py-1 bg-[var(--surface-2)] uppercase tracking-wider text-[var(--muted)]">
                  {tag} ({count})
                </span>
              ))}
            </div>
            
            <div className="space-y-4 mt-2 overflow-auto max-h-[32rem] pr-2">
              {profiles.map((profile) => (
                <div
                  key={profile.id}
                  className="border border-[var(--border)] p-4 hover:bg-[var(--surface-2)] transition-colors"
                >
                  <div className="flex gap-4 items-start">
                    <div className="w-10 h-10 border border-[var(--border)] bg-[var(--surface)] flex items-center justify-center shrink-0">
                      <Users className="w-5 h-5 text-[var(--muted)]" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-bold text-sm">
                        {profile.display_name}
                      </p>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-[10px] font-mono uppercase tracking-widest text-[var(--muted)]">
                        <span className="flex items-center gap-1">
                          <Building2 className="w-3 h-3" /> {profile.department || "N/A"}
                        </span>
                        <span className="flex items-center gap-1">
                          <GraduationCap className="w-3 h-3" /> {profile.year || "N/A"}
                        </span>
                        <span className="border border-[var(--border)] px-1 py-0.5">
                          {profile.attendee_type || "-"}
                        </span>
                      </div>
                      {profile.interests && (
                        <p className="text-[10px] font-mono uppercase text-[var(--muted)] mt-3 flex items-center gap-1.5 border-t border-[var(--border)] pt-2">
                          <Target className="w-3 h-3 text-[var(--verified)]" />
                          <span className="truncate">{profile.interests}</span>
                        </p>
                      )}
                    </div>
                  </div>

                  {profile.id !== selfProfileId && (
                    <button
                      className="mt-4 w-full btn-secondary text-xs py-2"
                      onClick={() => void connectWith(profile.id)}
                    >
                      <UserPlus className="w-3.5 h-3.5 mr-1" /> Connect
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Connections */}
          <div className="bg-[var(--surface)] border border-[var(--border)] p-6 space-y-4 h-fit">
            <h2 className="text-lg font-display font-medium">Connection Requests</h2>
            <div className="space-y-3">
              {connections.length === 0 ? (
                <div className="text-[11px] font-mono text-[var(--muted)] uppercase tracking-widest text-center py-4 border border-[var(--border)] border-dashed">
                  No active requests
                </div>
              ) : (
                connections.map((connection) => (
                  <div
                    key={connection.id}
                    className="border border-[var(--border)] p-3 flex flex-col gap-3"
                  >
                    <div className="flex items-center justify-between">
                      <p className="text-[10px] font-mono font-bold">
                        REQ #{connection.id.slice(0, 8)}
                      </p>
                      <span className="text-[10px] font-mono tracking-widest uppercase border border-[var(--border)] px-2 py-0.5 bg-[var(--surface-2)]">
                        {connection.status}
                      </span>
                    </div>
                    {connection.status === "pending" && (
                      <button
                        className="btn-primary text-xs py-1.5 w-full"
                        onClick={() => void acceptConnection(connection.id)}
                      >
                        Accept
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
            
            <div className="mt-6 p-4 border border-[var(--brass)] bg-[var(--brass)]/10 text-[var(--brass)]">
              <p className="text-[11px] font-mono uppercase tracking-widest leading-relaxed">
                Note: Messaging is intentionally disabled to keep Riwaq focused on event collaboration and trusted discovery.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
