import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Plus, Trash2, X, AlertTriangle, ArrowRight, Download, Upload,
  CheckCircle2, HardDrive, ChevronDown, RefreshCw, ArrowUpCircle,
} from "lucide-react";
import AboutPanel from "./AboutPanel";
import logoUrl from "../assets/logo.png";
import { useConfirm } from "../ui/confirm";
import { clearProfileStorage } from "../util/profileStorage";
import { onceUntilReload } from "../util/updateCheck";

// Result of the GitHub release check (backend: about::check_for_updates).
// `has_update` is true only when `latest` is a strictly newer semver than the
// running build. Mirrors the shape AboutPanel already consumes.
interface UpdateInfo { current: string; latest: string | null; has_update: boolean; release_url: string | null; }

const checkForUpdatesOnce = onceUntilReload(() => invoke<UpdateInfo>("check_for_updates"));

interface Props {
  onUnlocked: (profileName: string) => void;
}

const ProfileSelectPage = ({ onUnlocked }: Props) => {
  const [profiles, setProfiles] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // The expanded profile (by name). It expands to a password field + Open +
  // its actions.
  const [selected, setSelected] = useState<string>("");
  const [password, setPassword] = useState("");

  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newConfirmPassword, setNewConfirmPassword] = useState("");

  // Import is a two-step flow: pick file (backend validates header) → prompt
  // for the profile name to save it under. We keep the picked path here so
  // the second step can pass it back to Rust on commit.
  const [importStaged, setImportStaged] = useState<{ sourcePath: string; name: string } | null>(null);
  const [aboutOpen, setAboutOpen] = useState(false);

  // A newer published release than the running build, if any. Set only when
  // one actually exists, so the notice by "About" appears solely when there's
  // something to announce.
  const [update, setUpdate] = useState<UpdateInfo | null>(null);

  const confirm = useConfirm();

  const passwordInputRef = useRef<HTMLInputElement | null>(null);
  const nameInputRef = useRef<HTMLInputElement | null>(null);
  const importNameRef = useRef<HTMLInputElement | null>(null);

  // Clean the "[PREFIX] CODE:" off backend errors so the user reads the sentence.
  const cleanErr = (e: unknown) => String(e).replace(/^\[[A-Z_]+\]\s*(?:[A-Z_]+:\s*)?/, "");

  // One action at a time. The buttons are disabled while `busy`, but the Enter-key
  // handlers on the inputs are not — a second Enter (or a double click) used to
  // start a second unlock/create while the first was still deriving its key.
  // That meant two Argon2 runs, two vault loads and `onUnlocked` firing twice.
  // A ref, not state, so the very next event already sees it.
  const inFlight = useRef(false);
  const exclusive = async (fn: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    try { await fn(); } finally { inFlight.current = false; }
  };

  const reload = async () => {
    setLoading(true); setError(null);
    try {
      const list = await invoke<string[]>("list_profiles");
      setProfiles(list);
      setSelected((prev) => (prev && list.includes(prev) ? prev : list[0] || ""));
    } catch (e: any) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, []);

  // Check GitHub for a newer release, once per launch however often this page
  // comes back. Best-effort and silent: the fetch+semver-compare happens in
  // Rust (about::check_for_updates), and any failure — offline, rate-limited,
  // no releases — simply shows nothing.
  useEffect(() => {
    checkForUpdatesOnce()
      .then((u) => { if (u.has_update && u.latest) setUpdate(u); })
      .catch(() => {});
  }, []);

  const openReleaseNotes = () => {
    if (update?.release_url) invoke("open_external_url", { url: update.release_url }).catch(() => {});
  };

  // When the expanded row changes, reset + focus the password so opening a
  // profile is always "click row, type, Enter".
  useEffect(() => {
    setPassword("");
    setError(null);
    requestAnimationFrame(() => passwordInputRef.current?.focus());
  }, [selected]);

  useEffect(() => {
    if (creating) requestAnimationFrame(() => nameInputRef.current?.focus());
  }, [creating]);

  const toggle = (name: string) => setSelected((prev) => (prev === name ? "" : name));

  const unlockSelected = () => exclusive(async () => {
    if (!selected) { setError("Pick a profile first."); return; }
    if (!password) { setError("Type your password."); return; }
    setBusy(true); setError(null);
    try {
      await invoke("select_profile", { name: selected });
      await invoke("setup_master_db", { password });
      onUnlocked(selected);
    } catch (e: any) {
      const raw = String(e);
      setError(raw.toLowerCase().includes("decrypt") ? "Wrong password." : cleanErr(raw));
    } finally {
      setBusy(false);
    }
  });

  const createNew = () => exclusive(async () => {
    setError(null);
    if (!newName.trim()) { setError("Pick a name."); return; }
    if (!newPassword) { setError("Set a password."); return; }
    // The backend enforces this too — say it here so the rule shows up while
    // they're still typing, not as a rejection after they've confirmed it twice.
    // Count code points like the backend does (`.length` counts UTF-16 units,
    // so an emoji would count twice).
    if ([...newPassword].length < 8) { setError("Use at least 8 characters — this password protects every saved credential."); return; }
    if (newPassword !== newConfirmPassword) { setError("Passwords don't match."); return; }
    setBusy(true);
    try {
      await invoke("create_profile", { name: newName.trim(), password: newPassword });
      // A new profile never inherits what an older one of that name left
      // in localStorage (F-070).
      clearProfileStorage(newName.trim());
      onUnlocked(newName.trim());
    } catch (e: any) {
      setError(cleanErr(e));
    } finally {
      setBusy(false);
    }
  });

  const exportProfile = (name: string) => exclusive(async () => {
    setBusy(true); setError(null); setInfo(null);
    try {
      // Returns the chosen path on success, null if the user cancelled the
      // save dialog. We only surface a toast in the success case.
      const saved = await invoke<string | null>("export_profile", { name });
      if (saved) setInfo(`Exported to ${saved}`);
    } catch (e: any) {
      setError(cleanErr(e));
    } finally {
      setBusy(false);
    }
  });

  const startImport = () => exclusive(async () => {
    setError(null); setInfo(null);
    setBusy(true);
    try {
      const picked = await invoke<[string, string] | null>("import_profile_pick");
      if (!picked) { setBusy(false); return; }
      const [sourcePath, suggested] = picked;
      setImportStaged({ sourcePath, name: suggested });
      requestAnimationFrame(() => importNameRef.current?.select());
    } catch (e: any) {
      setError(cleanErr(e));
    } finally {
      setBusy(false);
    }
  });

  const commitImport = () => exclusive(async () => {
    if (!importStaged) return;
    const trimmed = importStaged.name.trim();
    if (!trimmed) { setError("Pick a name for the imported profile."); return; }
    setBusy(true); setError(null);
    try {
      await invoke("import_profile_save", { sourcePath: importStaged.sourcePath, name: trimmed });
      clearProfileStorage(trimmed);
      setImportStaged(null);
      setInfo(`Imported as "${trimmed}". Open it with the original password.`);
      await reload();
      setSelected(trimmed);
    } catch (e: any) {
      setError(cleanErr(e));
    } finally {
      setBusy(false);
    }
  });

  // Permanently delete the on-disk encrypted vault. There is no other copy
  // unless the user exported one, so the confirm says so plainly.
  const removeLocal = (name: string) => exclusive(async () => {
    const ok = await confirm({
      title: "Delete profile",
      message: `Delete "${name}" from this device?\n\nThe encrypted file is deleted for good. If you haven't exported a copy, its servers, logins and keys are gone.`,
      destructive: true,
      okLabel: "Delete",
      // Irreversible: Enter alone must not do it (F-048).
      typeToConfirm: name,
    });
    if (!ok) return;
    setBusy(true); setError(null);
    try {
      await invoke("delete_profile", { name });
      // Its remembered folders and bookmarks go with it (F-070).
      clearProfileStorage(name);
      await reload();
    } catch (e: any) {
      setError(cleanErr(e));
    } finally {
      setBusy(false);
    }
  });

  const inputBase =
    "w-full h-11 px-4 bg-zinc-900/40 border border-white/5 rounded-xl text-[14px] text-zinc-50 placeholder:text-zinc-600 outline-none focus:border-primary/50 focus:bg-zinc-900/60 transition-colors";

  // First run (no profiles yet) drops straight into create. `creating` is the
  // explicit "New profile" toggle.
  const showCreate = creating || (!loading && profiles.length === 0);

  return (
    <div className="flex-1 flex items-center justify-center px-6 py-10 bg-background">
      <div className="w-full max-w-[340px] flex flex-col">
        {/* Brand */}
        <div className="flex flex-col items-center mb-8 select-none">
          <img
            src={logoUrl}
            alt=""
            draggable={false}
            className="h-28 w-auto max-w-full object-contain mb-4 drop-shadow-[0_0_32px_rgba(var(--primary),0.22)]"
          />
          <h1 className="text-[22px] font-semibold text-white tracking-tight leading-none">Solanum</h1>
          <p className="text-[12.5px] text-zinc-500 mt-2">
            {loading
              ? " "
              : showCreate
                ? (profiles.length === 0 ? "Let's set up your first profile." : "Create a new profile.")
                : null}
          </p>
        </div>

        {error && (
          <div className="mb-3 px-3 py-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-200 text-[12.5px] flex items-center gap-2">
            <AlertTriangle size={13} className="shrink-0" /> {error}
          </div>
        )}

        {info && !error && (
          <div className="mb-3 px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-100 text-[12.5px] flex items-center gap-2">
            <CheckCircle2 size={13} className="shrink-0" /> <span className="truncate flex-1">{info}</span>
            <button onClick={() => setInfo(null)} className="text-emerald-200/70 hover:text-white shrink-0"><X size={13} /></button>
          </div>
        )}

        {importStaged && (
          <div className="mb-3 px-3 py-3 bg-zinc-900/60 border border-primary/30 rounded-lg space-y-2 animate-in fade-in">
            <div className="text-[11.5px] text-zinc-300 leading-snug">
              Importing a profile. Pick a name (the file's password is unchanged).
            </div>
            <input
              ref={importNameRef}
              value={importStaged.name}
              onChange={(e) => setImportStaged({ ...importStaged, name: e.target.value })}
              onKeyDown={(e) => e.key === "Enter" && commitImport()}
              className={inputBase + " h-9 text-[13px]"}
              placeholder="Profile name"
            />
            <div className="flex gap-2">
              <button
                onClick={commitImport}
                disabled={busy || !importStaged.name.trim()}
                className="flex-1 h-9 rounded-lg text-[12.5px] font-semibold bg-primary text-black disabled:opacity-50"
              >
                {busy ? "Importing…" : "Import"}
              </button>
              <button
                onClick={() => { setImportStaged(null); setError(null); }}
                className="h-9 px-3 rounded-lg text-[12.5px] font-semibold text-zinc-300 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {loading ? (
          <div className="text-center text-zinc-500 text-[12.5px] py-6">Loading…</div>
        ) : showCreate ? (
          /* ---- Create a profile ---- */
          <div className="space-y-3 animate-in fade-in">
            <input
              ref={nameInputRef}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Profile name"
              className={inputBase}
            />
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Password"
              className={inputBase}
            />
            <input
              type="password"
              value={newConfirmPassword}
              onChange={(e) => setNewConfirmPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && createNew()}
              placeholder="Confirm password"
              className={inputBase}
            />
            <button
              onClick={createNew}
              disabled={busy}
              className="w-full h-11 rounded-xl text-[14px] font-semibold bg-primary text-black hover:shadow-[0_0_24px_rgba(var(--primary),0.3)] disabled:opacity-50 flex items-center justify-center transition-all"
            >
              {busy ? "Creating…" : "Create profile"}
            </button>

            <div className="flex gap-2 pt-1">
              {profiles.length > 0 && (
                <button
                  onClick={() => { setCreating(false); setNewName(""); setNewPassword(""); setNewConfirmPassword(""); setError(null); }}
                  className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5"
                >
                  <X size={12} /> Cancel
                </button>
              )}
              <button
                onClick={startImport}
                disabled={busy}
                title="Import an exported .solanum file"
                className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
              >
                <Upload size={12} /> Import
              </button>
            </div>

            <p className="text-[11.5px] text-zinc-500 leading-relaxed text-center px-2 pt-1">
              Profiles are encrypted. If you forget the password, the data is gone for good.
            </p>
          </div>
        ) : (
          /* ---- Your profiles ---- */
          <div className="space-y-3">
            <div className="flex items-center justify-between px-0.5">
              <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">Your profiles</span>
            </div>

            <div className="rounded-xl border border-white/5 bg-white/[0.02] overflow-hidden divide-y divide-white/5">
              {profiles.map((name) => {
                const open = selected === name;
                return (
                  <div key={name}>
                    <button
                      onClick={() => toggle(name)}
                      className={`w-full flex items-center gap-2.5 px-3 h-11 text-left transition-colors ${open ? "bg-white/[0.03]" : "hover:bg-white/[0.02]"}`}
                    >
                      <HardDrive size={13} className="text-zinc-500 shrink-0" />
                      <span className="flex-1 min-w-0 truncate text-[13.5px] text-zinc-100">{name}</span>
                      <ChevronDown size={13} className={`text-zinc-600 shrink-0 transition-transform ${open ? "rotate-180" : ""}`} />
                    </button>

                    {open && (
                      <div className="px-3 pb-3 pt-1 bg-black/20 space-y-2.5 animate-in fade-in">
                        <div className="flex gap-2">
                          <input
                            ref={passwordInputRef}
                            type="password"
                            placeholder="Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            onKeyDown={(e) => e.key === "Enter" && unlockSelected()}
                            className="flex-1 h-10 px-3.5 bg-zinc-900/50 border border-white/5 rounded-lg text-[13.5px] text-zinc-50 placeholder:text-zinc-600 outline-none focus:border-primary/50 transition-colors"
                          />
                          <button
                            onClick={unlockSelected}
                            disabled={busy || !password}
                            title="Open"
                            className="h-10 px-3.5 rounded-lg text-[13px] font-semibold bg-primary text-black hover:shadow-[0_0_20px_rgba(var(--primary),0.3)] disabled:opacity-40 flex items-center gap-1.5 shrink-0 transition-all"
                          >
                            {busy ? <RefreshCw size={14} className="animate-spin" /> : <>Open <ArrowRight size={14} /></>}
                          </button>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <RowAction onClick={() => exportProfile(name)} disabled={busy} icon={<Download size={12} />} label="Export" />
                          <RowAction onClick={() => removeLocal(name)} disabled={busy} icon={<Trash2 size={12} />} label="Delete" danger />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="flex gap-2 pt-0.5">
              <button
                onClick={() => setCreating(true)}
                className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5"
              >
                <Plus size={12} /> New profile
              </button>
              <button
                onClick={startImport}
                disabled={busy}
                title="Import an exported .solanum file"
                className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
              >
                <Upload size={12} /> Import
              </button>
            </div>
          </div>
        )}

        {/* About, with a live "new version" notice underneath when one is
            available. */}
        <div className="mt-4 flex flex-col items-center gap-2.5">
          <button
            onClick={() => setAboutOpen(true)}
            className="h-8 px-4 rounded-lg text-[12.5px] font-bold text-zinc-200 bg-white/[0.04] border border-white/10 hover:bg-white/[0.09] hover:text-white transition-colors"
          >
            About
          </button>
          {update?.has_update && update.latest && (
            <button
              onClick={openReleaseNotes}
              title="Open the release notes on GitHub"
              className="group flex items-center gap-1.5 text-[10.5px] text-primary/90 hover:text-primary animate-in fade-in slide-in-from-bottom-1 duration-700"
            >
              {/* pulsing dot — the "something new" signal */}
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary/70 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-primary" />
              </span>
              <ArrowUpCircle size={11} className="shrink-0" />
              <span>New version <span className="font-mono font-semibold">v{update.latest}</span> available</span>
              <span className="opacity-60 transition-transform group-hover:translate-x-0.5">→</span>
            </button>
          )}
        </div>
      </div>

      <AboutPanel isOpen={aboutOpen} onClose={() => setAboutOpen(false)} />
    </div>
  );
};

// A compact secondary action inside an expanded row.
const RowAction = ({
  onClick, disabled, icon, label, danger,
}: {
  onClick: () => void; disabled?: boolean; icon: React.ReactNode; label: string; danger?: boolean;
}) => (
  <button
    onClick={onClick}
    disabled={disabled}
    title={label}
    className={`h-7 px-2 rounded-md text-[11px] font-medium border flex items-center gap-1 disabled:opacity-40 transition-colors ${
      danger
        ? "text-rose-300/90 bg-rose-500/5 border-rose-500/15 hover:bg-rose-500/15 hover:text-rose-200"
        : "text-zinc-400 bg-white/[0.03] border-white/10 hover:bg-white/[0.07] hover:text-zinc-100"
    }`}
  >
    {icon} {label}
  </button>
);

export default ProfileSelectPage;
