import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Server, Cpu, MemoryStick, HardDrive, ArrowUp, ArrowDown, Clock, Users } from "lucide-react";
import Sparkline from "./Sparkline";

// MobaXterm-style always-visible status row for the session Info tab's
// System sub-tab — the one thing that panel was missing versus a one-shot
// snapshot: live CPU% (with a small trend graph), RAM used/total, and
// network throughput, refreshing every second. Backed by ssh_info_live_sample
// (lib.rs), which reuses crate::monitor's own probe script and CPU%/network
// diff math but runs it over this session's own connection — see that
// command's comment for why it can't just reuse monitor.rs's poller outright
// (no ProxyJump support there).
//
// Self-contained auto-refresh, same shape as ProcessesTab's in this same
// file: a `winShown` listener so a minimized app window doesn't keep
// polling over SSH, gated additionally on `visible` (the in-app Info tab
// being the one on screen) — fixed 1s cadence, not user-configurable, to
// match the MobaXterm status line this is modeled on.

interface LiveInfoSample {
  cpu_pct: number | null;
  mem_total_kb: number;
  mem_avail_kb: number;
  disk_total_kb: number;
  disk_used_kb: number;
  net_in_bps: number | null;
  net_out_bps: number | null;
}

interface Props {
  sessionId: string;
  /** True while the underlying SSH session is disconnected. */
  disabled?: boolean;
  visible?: boolean;
  os: string;
  uptime: string;
  users: number | null;
}

const HISTORY = 40;

function formatGb(kb: number): string {
  return `${(kb / 1024 / 1024).toFixed(1)} GB`;
}

function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / 1024 / 1024).toFixed(1)} MB/s`;
}

// No per-distro logos (lucide-react ships no brand marks, and embedding real
// Ubuntu/Debian/RedHat/etc. logos raises asset-sourcing and trademark
// questions not worth it here) — just a generic server glyph, color-tinted
// by OS family so the strip isn't entirely monochrome.
function osAccentColor(os: string): string {
  const s = os.toLowerCase();
  if (s.includes("ubuntu") || s.includes("debian")) return "#e95420";
  if (s.includes("fedora") || s.includes("red hat") || s.includes("centos") || s.includes("rocky") || s.includes("alma")) return "#ee0000";
  if (s.includes("alpine")) return "#0d597f";
  if (s.includes("arch")) return "#1793d1";
  if (s.includes("suse")) return "#73ba25";
  if (s.includes("darwin") || s.includes("mac") || s.includes("bsd")) return "#a1a1aa";
  if (s.includes("windows")) return "#00a4ef";
  return "#71717a";
}

// One metric per line — icon, short label, right-aligned value. Module-level
// since it holds no state of its own; a component nested in a render
// function would remount every render for no benefit.
function Row({ icon, label, children, title }: { icon: ReactNode; label: string; children: ReactNode; title?: string }) {
  return (
    <div className="flex items-center gap-2" title={title}>
      {icon}
      <span className="text-zinc-500 w-14 shrink-0">{label}</span>
      <span className="flex-1 min-w-0 flex items-center justify-end gap-1 font-mono tabular-nums text-right">{children}</span>
    </div>
  );
}

const LiveStatusBar = ({ sessionId, disabled = false, visible = true, os, uptime, users }: Props) => {
  const [sample, setSample] = useState<LiveInfoSample | null>(null);
  const [cpuHistory, setCpuHistory] = useState<number[]>([]);

  const [winShown, setWinShown] = useState(() => typeof document === "undefined" || !document.hidden);
  useEffect(() => {
    const onVis = () => setWinShown(!document.hidden);
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, []);

  // Cleared on session change (switching between session tabs that share
  // this component's mount, since SessionView keeps tools mounted across
  // switches) and whenever the session disconnects, so the strip shows a
  // clean "—" instead of numbers frozen at the moment of disconnect sitting
  // right below the panel's own "Session is not connected" banner.
  const sessionIdRef = useRef(sessionId);
  useEffect(() => {
    if (sessionIdRef.current !== sessionId || disabled) {
      sessionIdRef.current = sessionId;
      setSample(null);
      setCpuHistory([]);
    }
  }, [sessionId, disabled]);

  // The session whose sample is on its way: a tick that finds one skips, so a
  // slow server never has several probes (channels) open for the strip (F-039).
  const inFlight = useRef<string | null>(null);
  const fetchNow = useCallback(async () => {
    if (disabled || !visible || !winShown) return;
    if (inFlight.current === sessionId) return;
    inFlight.current = sessionId;
    try {
      const s = await invoke<LiveInfoSample>("ssh_info_live_sample", { sessionId });
      // An answer for a session no longer shown is dropped.
      if (sessionIdRef.current !== sessionId) return;
      setSample(s);
      if (s.cpu_pct != null) {
        setCpuHistory((prev) => [...prev, s.cpu_pct as number].slice(-HISTORY));
      }
    } catch {
      // Transient probe failure (timeout, brief network hiccup) — keep
      // showing the last good sample rather than blanking the strip.
    } finally {
      if (inFlight.current === sessionId) inFlight.current = null;
    }
  }, [sessionId, disabled, visible, winShown]);

  useEffect(() => { if (!disabled && visible && winShown) fetchNow(); }, [fetchNow, disabled, visible, winShown]);
  useEffect(() => {
    if (disabled || !visible || !winShown) return;
    const id = setInterval(fetchNow, 1000);
    return () => clearInterval(id);
  }, [disabled, visible, winShown, fetchNow]);

  const memUsedKb = sample ? sample.mem_total_kb - sample.mem_avail_kb : 0;

  return (
    <div className="flex flex-col gap-1.5 px-3 py-2.5 bg-[#121215] border border-white/5 rounded-xl text-[11px] text-zinc-300">
      <div className="flex items-center gap-2 min-w-0" title={os || "Unknown OS"}>
        <Server size={13} className="shrink-0" style={{ color: osAccentColor(os) }} />
        <span className="font-bold text-zinc-100 truncate">{os || "—"}</span>
      </div>

      <Row icon={<Cpu size={12} className="text-sky-400 shrink-0" />} label="CPU" title="CPU usage">
        <span className="w-9">{sample?.cpu_pct != null ? `${sample.cpu_pct.toFixed(0)}%` : "—"}</span>
        <div className="flex-1 h-4">
          <Sparkline data={cpuHistory} color="rgb(56,189,248)" height={16} min={0} max={100} />
        </div>
      </Row>

      <Row icon={<MemoryStick size={12} className="text-emerald-400 shrink-0" />} label="RAM" title="Memory used / total">
        {sample ? `${formatGb(memUsedKb)} / ${formatGb(sample.mem_total_kb)}` : "—"}
      </Row>

      <Row icon={<ArrowDown size={12} className="text-emerald-400 shrink-0" />} label="Network" title="Network throughput">
        <span>{sample?.net_in_bps != null ? formatSpeed(sample.net_in_bps) : "—"}</span>
        <ArrowUp size={12} className="text-rose-400 shrink-0 ml-1" />
        <span>{sample?.net_out_bps != null ? formatSpeed(sample.net_out_bps) : "—"}</span>
      </Row>

      <Row icon={<HardDrive size={12} className="text-amber-400 shrink-0" />} label="Disk" title="Disk usage (root filesystem)">
        {sample && sample.disk_total_kb > 0 ? `${Math.round((sample.disk_used_kb / sample.disk_total_kb) * 100)}%` : "—"}
      </Row>

      <Row icon={<Clock size={12} className="text-zinc-400 shrink-0" />} label="Uptime" title="Uptime">
        <span className="truncate">{uptime || "—"}</span>
      </Row>

      <Row icon={<Users size={12} className="text-zinc-400 shrink-0" />} label="Users" title="Logged-in users">
        {users ?? "—"}
      </Row>
    </div>
  );
};

export default LiveStatusBar;
