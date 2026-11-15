import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ChevronDown, ChevronRight, RefreshCw } from "lucide-react";
import { COMMON_BAUDS, FLOWS, PARITIES, SerialSettings, serialSummary, type Flow, type Parity } from "../util/serialSettings";

// The port, speed and line settings of a serial server, shared by the server
// form and Quick connect. The port list comes from Rust (`list_serial_ports`,
// USB adapters first, names and descriptions already made safe to show); a
// port it does not list can be typed (Rust checks the name when saving and
// when opening).

interface PortEntry { name: string; description: string }

interface Props {
  value: SerialSettings;
  onChange: (next: SerialSettings) => void;
  inputClass: string;
  labelClass: string;
  /// Fold the line settings away behind their summary (Quick connect).
  foldLineSettings?: boolean;
}

const TYPED = "__typed__";
const OTHER_SPEED = "__other__";

const SerialPortFields = ({ value, onChange, inputClass, labelClass, foldLineSettings = false }: Props) => {
  const [ports, setPorts] = useState<PortEntry[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [typing, setTyping] = useState(false);
  const [otherSpeed, setOtherSpeed] = useState(!COMMON_BAUDS.includes(value.baud));
  const [lineOpen, setLineOpen] = useState(!foldLineSettings);

  const refresh = () => {
    setListError(null);
    invoke<PortEntry[]>("list_serial_ports")
      .then((list) => setPorts(list))
      .catch((e) => { setPorts([]); setListError(String(e)); });
  };
  useEffect(refresh, []);

  const listed = ports?.some((p) => p.name === value.port) ?? false;
  // A saved port this computer does not list (unplugged, or another computer's) is shown typed.
  const showTyped = typing || (value.port !== "" && ports !== null && !listed);
  const set = (patch: Partial<SerialSettings>) => onChange({ ...value, ...patch });

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <label className={labelClass}>Port</label>
          <button
            type="button"
            onClick={refresh}
            title="Look for ports again (after plugging an adapter in)"
            className="h-6 px-1.5 flex items-center gap-1 text-[10.5px] text-zinc-500 hover:text-white rounded transition-all"
          >
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
        <select
          className={inputClass}
          value={showTyped ? TYPED : value.port}
          onChange={(e) => {
            if (e.target.value === TYPED) {
              setTyping(true);
            } else {
              setTyping(false);
              set({ port: e.target.value });
            }
          }}
        >
          <option value="" disabled className="bg-[#1a1a1e] text-zinc-500">
            {ports === null ? "Looking for ports…" : ports.length === 0 ? "No serial port found" : "Choose a port"}
          </option>
          {ports?.map((p) => (
            <option key={p.name} value={p.name} className="bg-[#1a1a1e] text-white">
              {p.description ? `${p.name} — ${p.description}` : p.name}
            </option>
          ))}
          <option value={TYPED} className="bg-[#1a1a1e] text-white">Type a port name…</option>
        </select>
        {showTyped && (
          <input
            type="text"
            className={`${inputClass} font-mono`}
            placeholder="COM3, /dev/ttyUSB0 or /dev/cu.usbserial-1410"
            value={value.port}
            onChange={(e) => set({ port: e.target.value })}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
        )}
        {listError && <p className="text-[10.5px] text-rose-400 ml-1">The ports could not be listed: {listError}</p>}
      </div>

      <div className="space-y-1.5">
        <label className={labelClass}>Speed (baud)</label>
        <div className="flex gap-2">
          <select
            className={inputClass}
            value={otherSpeed ? OTHER_SPEED : String(value.baud)}
            onChange={(e) => {
              if (e.target.value === OTHER_SPEED) {
                setOtherSpeed(true);
              } else {
                setOtherSpeed(false);
                set({ baud: parseInt(e.target.value) });
              }
            }}
          >
            {COMMON_BAUDS.map((b) => <option key={b} value={String(b)} className="bg-[#1a1a1e] text-white">{b}</option>)}
            <option value={OTHER_SPEED} className="bg-[#1a1a1e] text-white">Other…</option>
          </select>
          {otherSpeed && (
            <input
              type="number"
              min={50}
              max={4000000}
              className={`${inputClass} font-mono`}
              value={Number.isNaN(value.baud) ? "" : value.baud}
              onChange={(e) => set({ baud: e.target.value === "" ? NaN : Number(e.target.value) })}
            />
          )}
        </div>
      </div>

      <div className="space-y-1.5">
        <button
          type="button"
          onClick={() => setLineOpen((o) => !o)}
          className={`${labelClass} flex items-center gap-1 hover:text-white`}
        >
          {lineOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          Line settings
          <span className="font-mono font-normal text-zinc-500">{serialSummary(value).replace(/^\d+ /, "")}</span>
        </button>
        {lineOpen && (
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <label className={labelClass}>Data bits</label>
              <select className={inputClass} value={value.dataBits} onChange={(e) => set({ dataBits: parseInt(e.target.value) })}>
                {[8, 7, 6, 5].map((n) => <option key={n} value={n} className="bg-[#1a1a1e] text-white">{n}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <label className={labelClass}>Parity</label>
              <select className={inputClass} value={value.parity} onChange={(e) => set({ parity: e.target.value as Parity })}>
                {PARITIES.map((p) => <option key={p.value} value={p.value} className="bg-[#1a1a1e] text-white">{p.label}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <label className={labelClass}>Stop bits</label>
              <select className={inputClass} value={value.stopBits} onChange={(e) => set({ stopBits: parseInt(e.target.value) })}>
                {[1, 2].map((n) => <option key={n} value={n} className="bg-[#1a1a1e] text-white">{n}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <label className={labelClass}>Flow control</label>
              <select className={inputClass} value={value.flow} onChange={(e) => set({ flow: e.target.value as Flow })}>
                {FLOWS.map((f) => <option key={f.value} value={f.value} className="bg-[#1a1a1e] text-white">{f.label}</option>)}
              </select>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SerialPortFields;
