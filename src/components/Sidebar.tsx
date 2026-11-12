import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Server, KeyRound, Library, Activity, Settings, LogOut, Pin, LayoutGrid } from "lucide-react";

const DEFAULT_ITEMS = [
  { id: 'nodes', icon: Server, label: 'Servers', kind: 'tab' },
  { id: 'vault', icon: KeyRound, label: 'Logins', kind: 'tab' },
  { id: 'library', icon: Library, label: 'Library', kind: 'tab' },
  { id: 'monitor', icon: Activity, label: 'Monitor', kind: 'tab' },
  { id: 'wall', icon: LayoutGrid, label: 'Wall', kind: 'tab' },
  // A toggle, not a tab (it opens/closes a side panel rather than switching
  // activeTab) — but on desktop it lives in the same reorderable rail as
  // everything else, so it needs a slot in this same list. Kept out of the
  // mobile dock at render time instead (the panel it controls is desktop-only).
  { id: 'pin-toggle', icon: Pin, label: 'Pinned panel', kind: 'toggle' },
];
const ORDER_KEY = "solanum-sidebar-order";

// Read a custom order from localStorage and apply it to DEFAULT_ITEMS. Any
// stored id that no longer matches a real item is dropped, and any real item
// missing from the stored order (e.g. Wall, added after someone already
// customized their order) is appended at the end in its default position —
// so a schema/feature change never hides an item just because it predates
// the saved preference.
function loadOrderedItems() {
  let storedIds: string[] = [];
  try {
    storedIds = JSON.parse(localStorage.getItem(ORDER_KEY) || "[]");
  } catch { /* fall through to default order */ }
  const byId = new Map(DEFAULT_ITEMS.map((it) => [it.id, it]));
  const ordered = storedIds.map((id) => byId.get(id)).filter(Boolean) as typeof DEFAULT_ITEMS;
  const seen = new Set(ordered.map((it) => it.id));
  for (const it of DEFAULT_ITEMS) {
    if (!seen.has(it.id)) ordered.push(it);
  }
  return ordered;
}

// Vertical rail on desktop, horizontal bottom dock on mobile. Layout swap is
// driven by `isMobile` so the terminal/session views can use the full screen
// width on phones — vertical sidebars eat ~50px of width that's expensive on
// a 360px-wide viewport. The parent in DesktopApp uses `flex-col-reverse` on
// mobile so this component visually lands at the bottom while staying first
// in DOM order (keyboard tab-order stays intuitive).
export const Sidebar = ({ activeTab, setActiveTab, isMobile, onLogout, pinnedPanelOpen, onTogglePinnedPanel }: any) => {
  // Commands + Notes used to be separate rails. Both are per-profile lists
  // of small text blobs stored under the vault; the only real distinction
  // was "runnable snippet vs freeform prose". A single Library rail with
  // an internal segmented control uses one sidebar slot instead of two —
  // room the user asked us to give back on narrow viewports.
  // "Tile two sessions together" moved out of a dedicated Compare rail
  // and into a per-session-tab "Merge into current view" action — the
  // sidebar stays focused on the persistent-content activities (Servers,
  // Logins, Library, Monitor, Wall) so it isn't padded with a workflow that
  // only makes sense while sessions are open.
  // Wall used to be reachable only via an icon that appears once a session
  // is already open, which meant it was invisible to anyone who'd never
  // opened one. Its own empty state already explains what it's for ("pin
  // any terminal from any server"), so it earns a permanent spot here too.
  const [items, setItems] = useState(loadOrderedItems);
  // Only desktop exposes the drag interaction (mouse-drag is awkward on
  // touch without more work than this warrants), but mobile's dock still
  // reflects whatever order was last saved on desktop — one shared source
  // of truth, just one input method for changing it.
  const [draggedId, setDraggedId] = useState<string | null>(null);
  // Live, in-progress preview of the order while dragging — distinct from
  // `items` (the committed order), the same split NodeGrid draws between
  // its own `order` state and the underlying source-of-truth list. Only
  // written to on drop.
  const [liveOrder, setLiveOrder] = useState<string[] | null>(null);
  const liveOrderRef = useRef<string[] | null>(null);
  const initialOrderRef = useRef<string[]>([]);
  const navRef = useRef<HTMLElement>(null);
  const cloneRef = useRef<HTMLDivElement>(null);
  const pointerRef = useRef({ x: 0, y: 0 });
  const grabOffsetRef = useRef({ x: 0, y: 0 });
  const itemSizeRef = useRef({ w: 40, h: 40 });
  // Fixed Y-centers of each icon's slot, snapshotted once at drag start —
  // never re-measured mid-drag. These are geometric slot positions, not
  // tied to which item currently occupies them, so they stay valid even as
  // `liveOrder` reshuffles which icon renders in which slot. Same reasoning
  // as NodeGrid's `slotsRef`: computing against live (already-reordered)
  // rects would make the insertion math chase its own tail.
  const slotsRef = useRef<number[]>([]);
  const rafRef = useRef<number | null>(null);

  // Pointer-based drag, not native HTML5 drag-and-drop — the latter is
  // unreliable inside WebKitGTK (this app's Linux webview), which is why
  // NodeGrid's own server reordering already uses pointer events instead.
  // Matching that proven approach rather than fighting the native API here.
  // True once a drag actually moves, so the click synthesized on pointerup
  // doesn't also activate whatever icon the pointer lands on. Cleared next
  // tick — same pattern NodeGrid uses for its own drag-vs-click distinction.
  const draggedRef = useRef(false);

  const beginDrag = (e: React.PointerEvent, id: string) => {
    // No preventDefault here, unlike NodeGrid's beginDrag — NodeGrid calls it
    // on a dedicated drag-handle element, separate from the clickable card.
    // This button is both the drag handle and the click target, and in
    // WebKitGTK, preventDefault() on pointerdown suppresses the click event
    // synthesized afterward — it broke tapping an icon to switch tabs.
    const btn = e.currentTarget as HTMLElement;
    const r = btn.getBoundingClientRect();
    grabOffsetRef.current = { x: e.clientX - r.left, y: e.clientY - r.top };
    itemSizeRef.current = { w: r.width, h: r.height };
    pointerRef.current = { x: e.clientX, y: e.clientY };
    // Excludes the dragged item's own slot: `idx` below counts how many of
    // these are above the pointer, and that count is spliced straight into
    // `base`, which has already had draggedId filtered out. Snapshotting the
    // dragged item's own slot too would count it as "above the pointer" the
    // moment the pointer moves even slightly below it, overshooting the
    // insertion point by one on every downward drag.
    const nodes = navRef.current?.querySelectorAll<HTMLElement>('[data-item-id]');
    slotsRef.current = nodes
      ? Array.from(nodes)
          .filter((el) => el.getAttribute('data-item-id') !== id)
          .map((el) => {
            const rr = el.getBoundingClientRect();
            return rr.top + rr.height / 2;
          })
      : [];
    const order = items.map((it) => it.id);
    initialOrderRef.current = order;
    liveOrderRef.current = order;
    setLiveOrder(order);
    setDraggedId(id);
  };

  useEffect(() => {
    if (draggedId === null) return;
    document.body.style.userSelect = 'none';
    // Insertion index, not nearest-neighbor — counts how many of the fixed
    // drag-start slots sit above the pointer, giving a 0..N index that
    // naturally supports dropping above the first icon or below the last
    // (including past the non-reorderable pin toggle), unlike "snap to
    // whichever icon is closest, then insert before it".
    const onMove = (e: PointerEvent) => {
      draggedRef.current = true;
      pointerRef.current = { x: e.clientX, y: e.clientY };
      if (cloneRef.current) {
        cloneRef.current.style.transform =
          `translate(${e.clientX - grabOffsetRef.current.x}px, ${e.clientY - grabOffsetRef.current.y}px) rotate(2deg) scale(1.05)`;
      }
      if (rafRef.current != null) return;
      const py = e.clientY;
      rafRef.current = requestAnimationFrame(() => {
        rafRef.current = null;
        let idx = 0;
        for (const y of slotsRef.current) {
          if (y < py) idx++;
        }
        const prev = liveOrderRef.current ?? initialOrderRef.current;
        const base = prev.filter((id) => id !== draggedId);
        const clamped = Math.max(0, Math.min(idx, base.length));
        base.splice(clamped, 0, draggedId);
        // Bail out if nothing actually moved since the last frame — without
        // this, every rAF tick during a drag calls setLiveOrder with a new
        // array reference even when its contents are identical, forcing a
        // re-render of the whole rail on every pixel of pointer movement.
        if (prev.length === base.length && prev.every((v, i) => v === base[i])) return;
        liveOrderRef.current = base;
        setLiveOrder(base);
      });
    };
    const onUp = () => {
      if (rafRef.current != null) { cancelAnimationFrame(rafRef.current); rafRef.current = null; }
      document.body.style.userSelect = '';
      const final = liveOrderRef.current;
      const initial = initialOrderRef.current;
      const changed = !!final && (final.length !== initial.length || final.some((v, i) => v !== initial[i]));
      if (changed && final) {
        setItems((prev) => {
          const byId = new Map(prev.map((it) => [it.id, it]));
          const reordered = final.map((id) => byId.get(id)).filter(Boolean) as typeof prev;
          try { localStorage.setItem(ORDER_KEY, JSON.stringify(final)); } catch { /* per-viewer convenience only */ }
          return reordered;
        });
      }
      setDraggedId(null);
      setLiveOrder(null);
      liveOrderRef.current = null;
      setTimeout(() => { draggedRef.current = false; }, 0);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      // Also reset here, not just in onUp — if this component unmounts
      // mid-drag (hot reload, or any future conditional-render path), onUp
      // never runs and userSelect would otherwise stay 'none' app-wide.
      document.body.style.userSelect = '';
    };
  }, [draggedId]);

  if (isMobile) {
    return (
      // `pb-[env(safe-area-inset-bottom)]` clears the Android gesture-nav pill
      // and iPhone home-indicator so the tab icons don't sit under system UI.
      // Height stays 56px minimum (h-14) via `min-h-14` — the extra padding
      // expands the aside downward into safe-area space, not upward into the
      // content area, so the terminal above doesn't lose vertical room.
      <aside
        style={{ paddingBottom: 'env(safe-area-inset-bottom)' }}
        className="w-full min-h-14 shrink-0 bg-background border-t border-white/5 flex items-center px-2 relative z-10 shadow-2xl brightness-95"
      >
        <nav className="flex-1 flex flex-row items-center justify-around gap-1">
          {items.filter((item) => item.kind !== 'toggle').map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`p-2.5 rounded-xl transition-all duration-300 relative group flex items-center justify-center ${
                activeTab === item.id
                  ? 'text-primary bg-primary/10 shadow-[0_0_20px_rgba(var(--primary),0.15)]'
                  : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/5'
              }`}
              title={item.label}
            >
              <item.icon size={20} className={activeTab === item.id ? "drop-shadow-[0_0_8px_rgba(var(--primary),0.5)]" : ""} />
              {/* Bottom indicator stripe instead of left rail in mobile mode. */}
              {activeTab === item.id && <div className="absolute bottom-0 left-1/2 -translate-x-1/2 h-0.5 w-1/2 bg-primary rounded-t-full shadow-[0_0_10px_rgba(var(--primary),1)]" />}
            </button>
          ))}
        </nav>

        {/* Trailing cluster (logout + settings) — kept at the right edge of
            the horizontal bar so the muscle-memory mapping "settings is the
            last icon" still holds, just now read left-to-right. */}
        <div className="flex items-center gap-1 pl-2 ml-1 border-l border-white/5">
          {onLogout && (
            <button
              onClick={onLogout}
              className="p-2.5 rounded-xl transition-all flex items-center justify-center text-zinc-300 hover:text-amber-300 hover:bg-amber-500/10"
              title="Lock & switch profile"
            >
              <LogOut size={20} />
            </button>
          )}
          <button
            onClick={() => setActiveTab('settings')}
            className={`p-2.5 rounded-xl transition-all flex items-center justify-center ${
              activeTab === 'settings'
                ? 'text-primary bg-primary/10 shadow-[0_0_20px_rgba(var(--primary),0.15)]'
                : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/5'
            }`}
            title="Settings"
          >
            <Settings size={20} className={activeTab === 'settings' ? "drop-shadow-[0_0_8px_rgba(var(--primary),0.5)]" : ""} />
          </button>
        </div>
      </aside>
    );
  }

  // While dragging, render in the live preview order so the rest of the
  // icons visibly shift to make room — that shift is what communicates the
  // drop position, rather than a separate highlight ring on a "nearest"
  // icon. `items` itself only updates once, on drop.
  const displayIds = draggedId !== null && liveOrder ? liveOrder : items.map((it) => it.id);
  const itemsById = new Map(items.map((it) => [it.id, it]));
  const draggedItem = draggedId !== null ? itemsById.get(draggedId) : undefined;

  return (
    <aside className="w-14 h-full bg-background border-r border-white/5 flex flex-col items-center py-6 shrink-0 relative z-10 shadow-2xl brightness-95 transition-all">
      <nav ref={navRef} className="flex flex-col gap-3 w-full px-2">
        {displayIds.map((id) => {
          const item = itemsById.get(id);
          if (!item) return null;
          // The pin toggle rides in this same reorderable list (it needs to
          // be draggable, and other icons need to be droppable below it),
          // but it opens/closes a panel rather than switching activeTab, and
          // its "active" state is pinnedPanelOpen rather than a tab match.
          const isToggle = item.kind === 'toggle';
          const isActive = isToggle ? !!pinnedPanelOpen : activeTab === item.id;
          const title = isToggle
            ? `${pinnedPanelOpen ? 'Hide' : 'Show'} pinned (drag to reorder)`
            : `${item.label} (drag to reorder)`;
          return (
            <button
              key={item.id}
              data-item-id={item.id}
              onPointerDown={(e) => beginDrag(e, item.id)}
              onClick={() => {
                if (draggedRef.current) return;
                if (isToggle) onTogglePinnedPanel?.();
                else setActiveTab(item.id);
              }}
              title={title}
              style={{ touchAction: 'none' }}
              className={`p-2.5 rounded-xl transition-all duration-300 relative group flex items-center justify-center ${
                // Driven by tracked drag state rather than the CSS :active
                // pseudo-class — :active didn't reliably follow the pointer
                // as it moved across sibling icons during the drag.
                draggedId !== null ? 'cursor-grabbing' : 'cursor-grab'
              } ${
                // Dimmed rather than swapped for a placeholder element while
                // it's the one being dragged — its own floating clone shows
                // the "real" icon under the cursor, but this stays the exact
                // same <button> throughout (same element type, same key) so
                // a plain press-and-release still fires its click normally.
                // Swapping it for a different element between pointerdown
                // and pointerup used to unmount the button the click was
                // about to land on.
                draggedId === item.id ? 'opacity-40' : ''
              } ${
                isActive
                  ? 'text-primary bg-primary/10 shadow-[0_0_20px_rgba(var(--primary),0.15)]'
                  : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/5'
              }`}
            >
              <item.icon size={20} className={isActive ? "drop-shadow-[0_0_8px_rgba(var(--primary),0.5)]" : ""} />
              {isActive && <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-1/2 bg-primary rounded-r-full shadow-[0_0_10px_rgba(var(--primary),1)]" />}
            </button>
          );
        })}
      </nav>

      {/* Bottom cluster: logout (lock current profile, return to picker)
          and settings. Logout sits above settings so the gear stays as the
          last-most icon — matches the muscle memory from when it was the
          only bottom action. Deliberately not reorderable, alongside the
          rest of this cluster — "settings/logout always last" is a settled
          convention, not something worth customizing. */}
      <div className="mt-auto w-full px-2 flex flex-col gap-2">
        {onLogout && (
          <button
            onClick={onLogout}
            className="p-2.5 rounded-xl transition-all flex items-center justify-center text-zinc-300 hover:text-amber-300 hover:bg-amber-500/10"
            title="Lock & switch profile"
          >
            <LogOut size={20} />
          </button>
        )}
        <button
          onClick={() => setActiveTab('settings')}
          className={`p-2.5 rounded-xl transition-all flex items-center justify-center ${
            activeTab === 'settings'
              ? 'text-primary bg-primary/10 shadow-[0_0_20px_rgba(var(--primary),0.15)]'
              : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/5'
          }`}
          title="Settings"
        >
          <Settings size={20} className={activeTab === 'settings' ? "drop-shadow-[0_0_8px_rgba(var(--primary),0.5)]" : ""} />
        </button>
      </div>

      {/* The "ghost" — a floating clone that tracks the pointer, portaled to
          <body> so it isn't clipped by this 56px-wide rail. Its transform is
          driven imperatively from the pointermove handler (not React state)
          so it moves every frame without a re-render; only its initial
          position comes from state, at mount. Same technique as NodeGrid's
          own dragged-card clone. */}
      {draggedId !== null && draggedItem && createPortal(
        <div
          ref={cloneRef}
          className="fixed left-0 top-0 z-[9999] pointer-events-none will-change-transform"
          style={{
            width: itemSizeRef.current.w,
            height: itemSizeRef.current.h,
            transform: `translate(${pointerRef.current.x - grabOffsetRef.current.x}px, ${pointerRef.current.y - grabOffsetRef.current.y}px) rotate(2deg) scale(1.05)`,
          }}
        >
          <div className="w-full h-full rounded-xl bg-primary/15 border border-primary/40 shadow-xl flex items-center justify-center text-primary">
            <draggedItem.icon size={20} className="drop-shadow-[0_0_8px_rgba(var(--primary),0.6)]" />
          </div>
        </div>,
        document.body
      )}
    </aside>
  );
};
