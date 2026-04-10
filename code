import { useState, useCallback, useEffect, useRef } from "react";

// =====================================================================
// GF(256) Shamir Secret Sharing
// =====================================================================
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x = x ^ (x << 1) ^ (x >= 128 ? 0x11b : 0); x &= 0xff; }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const gfMul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];
const gfDiv = (a, b) => { if (!b) throw new Error("÷0"); return a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255]; };
const evalPoly = (c, x) => { let r = 0; for (let i = c.length - 1; i >= 0; i--) r = gfMul(r, x) ^ c[i]; return r; };
function lagrange(pts) {
  let s = 0;
  for (let i = 0; i < pts.length; i++) {
    let n = 1, d = 1;
    for (let j = 0; j < pts.length; j++) { if (i === j) continue; n = gfMul(n, pts[j][0]); d = gfMul(d, pts[i][0] ^ pts[j][0]); }
    s ^= gfMul(pts[i][1], gfDiv(n, d));
  }
  return s;
}
function splitBytes(bytes, n, k) {
  const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, data: new Uint8Array(bytes.length) }));
  const rng = new Uint8Array(k - 1);
  for (let b = 0; b < bytes.length; b++) {
    crypto.getRandomValues(rng);
    const co = new Uint8Array(k); co[0] = bytes[b];
    for (let c = 1; c < k; c++) co[c] = rng[c - 1];
    for (let i = 0; i < n; i++) shares[i].data[b] = evalPoly(co, shares[i].x);
  }
  return shares;
}
function combineShares(shares) {
  if (!shares.length) return new Uint8Array(0);
  const len = shares[0].data.length;
  const r = new Uint8Array(len);
  for (let b = 0; b < len; b++) r[b] = lagrange(shares.map(s => [s.x, s.data[b]]));
  return r;
}
function toHex(share) {
  return share.x.toString(16).padStart(2, "0") + Array.from(share.data).map(b => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  const clean = hex.replace(/\s/g, "");
  const x = parseInt(clean.slice(0, 2), 16);
  const data = new Uint8Array((clean.length - 2) / 2);
  for (let i = 0; i < data.length; i++) data[i] = parseInt(clean.slice(2 + i * 2, 4 + i * 2), 16);
  return { x, data };
}

// BIP-39 validation
const VALID_COUNTS = [12, 15, 18, 21, 24];
function validateSeed(phrase) {
  const words = phrase.trim().toLowerCase().split(/\s+/);
  const errors = [];
  if (!VALID_COUNTS.includes(words.length)) errors.push(`Seed phrase must be 12, 15, 18, 21, or 24 words. You entered ${words.length}.`);
  const bad = words.filter(w => !/^[a-z]+$/.test(w));
  if (bad.length) errors.push(`Invalid characters in: ${bad.slice(0, 3).join(", ")}${bad.length > 3 ? "..." : ""}`);
  return { valid: !errors.length, errors, wordCount: words.length };
}

// =====================================================================
// Icons
// =====================================================================
const ShieldIcon = ({ size = 22 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);
const ShieldCheck = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>
  </svg>
);
const KeyIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="8" cy="15" r="5"/><path d="M11.7 11.3L17 6"/><path d="M15 8l2-2"/><path d="M17 6l2 2"/>
  </svg>
);
const LockIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
);
const WifiOff = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"/><path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"/>
    <path d="M10.71 5.05A16 16 0 0 1 22.56 9"/><path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>
  </svg>
);
const WifiOn = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>
  </svg>
);
const AlertTri = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);
const CopyIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
);
const CheckIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);
const TrashIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
    <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
  </svg>
);
const PlusIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
  </svg>
);
const EyeIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
  </svg>
);
const EyeOffIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
    <line x1="1" y1="1" x2="23" y2="23"/>
  </svg>
);
const MonitorIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
  </svg>
);
const PhoneIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>
  </svg>
);
const DownloadIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
  </svg>
);
const GearIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
  </svg>
);

// =====================================================================
// Copy button — light theme
// =====================================================================
function CopyBtn({ text, label = "Copy" }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1400); }} style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      background: ok ? "#ecfdf5" : "#f4f5f7", border: "1px solid " + (ok ? "#a7f3d0" : "#dfe3e8"),
      borderRadius: 6, padding: "5px 10px", fontSize: 11.5, fontWeight: 500,
      color: ok ? "#047857" : "#5a6577", cursor: "pointer", transition: "all 0.2s",
      fontFamily: "inherit", whiteSpace: "nowrap", flexShrink: 0,
    }}>
      {ok ? <CheckIcon /> : <CopyIcon />}{ok ? "Copied" : label}
    </button>
  );
}

// =====================================================================
// Network status
// =====================================================================
function useOnline() {
  const [on, setOn] = useState(typeof navigator !== "undefined" ? navigator.onLine : true);
  useEffect(() => {
    const a = () => setOn(true), b = () => setOn(false);
    window.addEventListener("online", a); window.addEventListener("offline", b);
    return () => { window.removeEventListener("online", a); window.removeEventListener("offline", b); };
  }, []);
  return on;
}

// =====================================================================
// Tokens — matching the Shamir tool's light professional palette
// =====================================================================
const NAVY = "#152040";
const ACCENT = "#2761e6";
const ACCENT_SOFT = "#eef3ff";
const BORDER = "#e4e8ee";
const TEXT_PRI = "#1c2a3d";
const TEXT_SEC = "#6b7a8d";
const CARD_BG = "rgba(255,255,255,0.88)";
const MONO = `'JetBrains Mono','SF Mono','Consolas','Menlo',monospace`;
const SANS = `'DM Sans',system-ui,sans-serif`;
const GREEN = "#059669";
const GREEN_BG = "#ecfdf5";
const GREEN_BD = "#a7f3d0";
const RED = "#dc2626";
const RED_BG = "#fef2f2";
const RED_BD = "#fecaca";
const AMBER_BG = "#fffbeb";
const AMBER_BD = "#fde68a";
const AMBER_TEXT = "#92400e";

// =====================================================================
// Main App
// =====================================================================
export default function SeedVault() {
  const [viewMode, setViewMode] = useState("auto"); // auto | mobile | desktop
  const [mode, setMode] = useState("split");
  const [step, setStep] = useState(1);
  const online = useOnline();

  const [phrase, setPhrase] = useState("");
  const [showPhrase, setShowPhrase] = useState(false);
  const [validation, setValidation] = useState(null);
  const [totalShares, setTotalShares] = useState(5);
  const [threshold, setThreshold] = useState(3);
  const [shares, setShares] = useState([]);

  const [inputShares, setInputShares] = useState(["", "", ""]);
  const [recovered, setRecovered] = useState(null);
  const [showRecovered, setShowRecovered] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (phrase.trim()) setValidation(validateSeed(phrase));
    else setValidation(null);
  }, [phrase]);

  const handleSplit = useCallback(() => {
    if (!validation?.valid) return;
    const bytes = new TextEncoder().encode(phrase.trim().toLowerCase().replace(/\s+/g, " "));
    setShares(splitBytes(bytes, totalShares, threshold).map(s => toHex(s)));
    setStep(3);
  }, [phrase, validation, totalShares, threshold]);

  const handleCombine = useCallback(() => {
    setError(""); setRecovered(null);
    try {
      const parsed = inputShares.filter(s => s.trim()).map(s => fromHex(s.trim()));
      if (parsed.length < 2) { setError("Provide at least 2 shares."); return; }
      const bytes = combineShares(parsed);
      const text = new TextDecoder().decode(bytes);
      const v = validateSeed(text);
      if (!v.valid) { setError("Shares combined but result doesn't look like a valid seed phrase. Check that you have enough shares and they're from the same set."); return; }
      setRecovered(text);
    } catch { setError("Invalid share format. Double-check your hex strings."); }
  }, [inputShares]);

  const resetSplit = () => { setStep(1); setShares([]); setPhrase(""); setValidation(null); setShowPhrase(false); };

  // Determine effective width constraint
  const isMobileForced = viewMode === "mobile";
  const isDesktopForced = viewMode === "desktop";
  const containerMaxW = isMobileForced ? 390 : 620;

  const css = `
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap');
    *,*::before,*::after{box-sizing:border-box;margin:0}
    body{margin:0;background:#f8f9fb}
    input:focus,textarea:focus{outline:none;border-color:${ACCENT}!important;box-shadow:0 0 0 3px rgba(39,97,230,0.1)!important}
    input::placeholder,textarea::placeholder{color:#b0b8c4}
    button{font-family:${SANS}}
    button:active{transform:scale(0.98)}
    input[type=range]{-webkit-appearance:none;appearance:none;height:5px;background:linear-gradient(90deg,${ACCENT},#93b4f5);border-radius:99px;outline:none;opacity:.7;transition:opacity .2s}
    input[type=range]:hover{opacity:1}
    input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;border-radius:50%;background:#fff;border:2.5px solid ${ACCENT};box-shadow:0 1px 6px rgba(0,0,0,.12);cursor:pointer}
    input[type=range]::-webkit-slider-thumb:hover{box-shadow:0 2px 10px rgba(39,97,230,.3)}
    input[type=range]::-moz-range-thumb{width:22px;height:22px;border-radius:50%;background:#fff;border:2.5px solid ${ACCENT};box-shadow:0 1px 6px rgba(0,0,0,.12);cursor:pointer}
    @keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
    @keyframes popIn{from{opacity:0;transform:scale(0.96)}to{opacity:1;transform:scale(1)}}
    .af{animation:fadeUp .45s cubic-bezier(.22,1,.36,1) both}
    .ap{animation:popIn .35s cubic-bezier(.22,1,.36,1) both}
    .sr{transition:background .15s,box-shadow .15s}
    .sr:hover{background:#f6f8fb!important;box-shadow:0 1px 4px rgba(0,0,0,.04)!important}
    .cta:hover{box-shadow:0 6px 20px rgba(21,32,64,.3)!important;transform:translateY(-1px)}
    .mobile-stack{grid-template-columns:1fr 1fr}
    @media(max-width:520px){.mobile-stack{grid-template-columns:1fr!important}}
    ${isMobileForced ? `.mobile-stack{grid-template-columns:1fr!important}` : ""}
  `;

  const card = {
    background: CARD_BG, border: `1px solid ${BORDER}`, borderRadius: 14,
    padding: isMobileForced ? 16 : "clamp(16px,4vw,24px)", marginBottom: 14,
    backdropFilter: "blur(16px)", boxShadow: "0 1px 3px rgba(0,0,0,0.03), 0 0 0 1px rgba(255,255,255,0.6) inset",
  };
  const label = {
    display: "flex", alignItems: "center", gap: 7, fontSize: 11.5, fontWeight: 600,
    color: NAVY, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 12,
  };
  const inputBase = {
    width: "100%", background: "#fafbfc", border: `1.5px solid ${BORDER}`, borderRadius: 8,
    padding: "12px 14px", color: TEXT_PRI, fontSize: 14, fontFamily: SANS,
    transition: "border-color .2s, box-shadow .2s",
  };

  return (
    <div style={{
      minHeight: "100vh", fontFamily: SANS, color: TEXT_PRI, position: "relative",
      background: "linear-gradient(170deg, #f0f3f8 0%, #f8f9fb 40%, #fff 100%)",
    }}>
      <style>{css}</style>

      {/* Dot grid */}
      <svg style={{ position: "fixed", inset: 0, width: "100%", height: "100%", zIndex: 0, pointerEvents: "none", opacity: 0.35 }}>
        <defs><pattern id="d" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="0.6" fill="#b4bcc8"/>
        </pattern></defs>
        <rect width="100%" height="100%" fill="url(#d)"/>
      </svg>

      <div style={{
        position: "relative", zIndex: 1, maxWidth: containerMaxW, margin: "0 auto",
        padding: isMobileForced
          ? "24px 16px 48px"
          : "clamp(28px,6vw,56px) clamp(16px,5vw,28px) 48px",
        transition: "max-width 0.4s ease, padding 0.4s ease",
      }}>

        {/* ---- Viewport toggle ---- */}
        <div className="af" style={{
          display: "flex", justifyContent: "flex-end", marginBottom: 12,
        }}>
          <div style={{
            display: "inline-flex", gap: 2, padding: 3,
            background: "#eaecf1", borderRadius: 9,
          }}>
            {[
              { key: "auto", label: "Auto" },
              { key: "mobile", label: null, icon: <PhoneIcon /> },
              { key: "desktop", label: null, icon: <MonitorIcon /> },
            ].map(v => (
              <button key={v.key} onClick={() => setViewMode(v.key)} title={v.key.charAt(0).toUpperCase() + v.key.slice(1)} style={{
                display: "flex", alignItems: "center", justifyContent: "center", gap: 4,
                padding: v.label ? "6px 12px" : "6px 10px",
                fontSize: 11.5, fontWeight: 600, border: "none", borderRadius: 7, cursor: "pointer",
                background: viewMode === v.key ? "#fff" : "transparent",
                color: viewMode === v.key ? NAVY : TEXT_SEC,
                boxShadow: viewMode === v.key ? "0 1px 4px rgba(0,0,0,.06)" : "none",
                transition: "all .2s",
              }}>
                {v.icon}{v.label}
              </button>
            ))}
          </div>
        </div>

        {/* ---- Network banner ---- */}
        <div className="af" style={{
          display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
          padding: "9px 16px", marginBottom: 18, borderRadius: 10,
          background: online ? RED_BG : GREEN_BG,
          border: `1px solid ${online ? RED_BD : GREEN_BD}`,
          fontSize: isMobileForced ? 11.5 : 12.5, fontWeight: 500,
          color: online ? RED : GREEN, lineHeight: 1.5,
        }}>
          {online ? <WifiOn /> : <WifiOff />}
          <span>{online
            ? "You are online. For maximum security, disconnect before entering your seed phrase."
            : "Offline — your seed phrase never leaves this device."
          }</span>
        </div>

        {/* ---- Header ---- */}
        <header className="af" style={{ textAlign: "center", marginBottom: isMobileForced ? 24 : "clamp(24px,4vw,36px)", animationDelay: ".05s" }}>
          <div style={{
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            width: 56, height: 56, borderRadius: 16, marginBottom: 16,
            background: `linear-gradient(145deg, ${NAVY}, #253560)`,
            boxShadow: `0 8px 24px rgba(21,32,64,.22), 0 0 0 1px rgba(255,255,255,.08) inset`,
          }}>
            <span style={{ color: "#fff", display: "flex" }}><ShieldIcon size={26} /></span>
          </div>
          <h1 style={{
            fontSize: isMobileForced ? 20 : "clamp(21px,4.5vw,27px)", fontWeight: 700, color: NAVY,
            letterSpacing: "-.025em", margin: "0 0 8px", lineHeight: 1.25,
          }}>
            Seed Phrase Vault
          </h1>
          <p style={{
            fontSize: isMobileForced ? 13 : "clamp(13px,2.5vw,14.5px)", color: TEXT_SEC,
            lineHeight: 1.55, maxWidth: 440, margin: "0 auto",
          }}>
            Protect your BIP-39 seed phrase with Shamir's Secret Sharing.
            Split into <em>n</em> shares — any <em>k</em> recover it, fewer reveal nothing.
          </p>
        </header>

        {/* ---- Tabs ---- */}
        <div className="af" style={{
          display: "flex", gap: 4, padding: 4, marginBottom: isMobileForced ? 18 : "clamp(18px,3.5vw,24px)",
          background: "#eaecf1", borderRadius: 11, animationDelay: ".08s",
        }}>
          {[
            { key: "split", label: "Split Phrase" },
            { key: "combine", label: "Recover Phrase" },
          ].map(t => (
            <button key={t.key} onClick={() => { setMode(t.key); setError(""); setRecovered(null); setShowRecovered(false); }} style={{
              flex: 1, padding: "11px 0", fontSize: 13, fontWeight: 600,
              border: "none", borderRadius: 9, cursor: "pointer",
              background: mode === t.key ? "#fff" : "transparent",
              color: mode === t.key ? NAVY : TEXT_SEC,
              boxShadow: mode === t.key ? "0 1px 5px rgba(0,0,0,.07), 0 0 0 1px rgba(0,0,0,.03)" : "none",
              transition: "all .25s",
            }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* =================== SPLIT STEP 1 =================== */}
        {mode === "split" && step === 1 && (
          <div className="af" style={{ animationDelay: ".1s" }}>
            <div style={card}>
              <div style={label}><KeyIcon /> Seed Phrase</div>
              <div style={{ position: "relative" }}>
                <textarea
                  style={{
                    ...inputBase, minHeight: 96, resize: "vertical", lineHeight: 1.7,
                    fontFamily: showPhrase ? MONO : SANS,
                    WebkitTextSecurity: showPhrase ? "none" : "disc",
                    letterSpacing: showPhrase ? ".02em" : ".15em",
                    fontSize: showPhrase ? 13.5 : 16,
                  }}
                  placeholder="Enter your 12 or 24 word seed phrase..."
                  value={phrase} onChange={e => setPhrase(e.target.value)}
                />
                <button onClick={() => setShowPhrase(!showPhrase)} style={{
                  position: "absolute", top: 10, right: 10,
                  background: "#fff", border: `1px solid ${BORDER}`, borderRadius: 6,
                  padding: "5px 9px", cursor: "pointer", color: TEXT_SEC,
                  display: "flex", alignItems: "center", gap: 4, fontSize: 11, fontFamily: SANS,
                }}>
                  {showPhrase ? <EyeOffIcon /> : <EyeIcon />}
                  {showPhrase ? "Hide" : "Show"}
                </button>
              </div>

              {validation && (
                <div style={{
                  marginTop: 10, padding: "8px 12px", borderRadius: 8, fontSize: 12.5, lineHeight: 1.5,
                  background: validation.valid ? GREEN_BG : RED_BG,
                  border: `1px solid ${validation.valid ? GREEN_BD : RED_BD}`,
                  color: validation.valid ? GREEN : RED,
                  display: "flex", alignItems: "flex-start", gap: 8,
                }}>
                  {validation.valid ? <ShieldCheck /> : <AlertTri />}
                  <span>{validation.valid ? `Valid format — ${validation.wordCount} words detected.` : validation.errors.join(" ")}</span>
                </div>
              )}

              <div style={{
                marginTop: 14, padding: "10px 12px", borderRadius: 8,
                background: AMBER_BG, border: `1px solid ${AMBER_BD}`,
                fontSize: 12, color: AMBER_TEXT, lineHeight: 1.6,
                display: "flex", alignItems: "flex-start", gap: 8,
              }}>
                <span style={{ flexShrink: 0, marginTop: 1 }}><AlertTri /></span>
                <span>Your seed phrase is processed entirely in your browser. It is never transmitted, stored, or logged. For maximum safety, disconnect from the internet first.</span>
              </div>
            </div>

            <button className="cta" disabled={!validation?.valid} onClick={() => setStep(2)} style={{
              width: "100%", padding: "14px 0", fontSize: 14, fontWeight: 600,
              border: "none", borderRadius: 10, cursor: validation?.valid ? "pointer" : "not-allowed",
              background: validation?.valid ? `linear-gradient(135deg, ${NAVY}, #253560)` : "#ced4dc",
              color: "#fff", letterSpacing: ".02em",
              boxShadow: validation?.valid ? "0 4px 16px rgba(21,32,64,.22)" : "none",
              transition: "all .3s",
            }}>
              Continue to Configuration
            </button>
          </div>
        )}

        {/* =================== SPLIT STEP 2 =================== */}
        {mode === "split" && step === 2 && (
          <div className="af" style={{ animationDelay: ".05s" }}>
            <div style={card}>
              <div style={label}><GearIcon /> Sharing Scheme</div>
              <div className="mobile-stack" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: isMobileForced ? 14 : "clamp(14px,3vw,20px)", marginBottom: 18 }}>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
                    <span style={{ fontSize: 13, color: TEXT_SEC, fontWeight: 500 }}>Total shares (n)</span>
                    <span style={{ fontSize: 24, fontWeight: 700, color: ACCENT, fontFamily: MONO, lineHeight: 1 }}>{totalShares}</span>
                  </div>
                  <input type="range" min={2} max={10} value={totalShares} style={{ width: "100%" }}
                    onChange={e => { const v = +e.target.value; setTotalShares(v); if (threshold > v) setThreshold(v); }} />
                </div>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
                    <span style={{ fontSize: 13, color: TEXT_SEC, fontWeight: 500 }}>Required to recover (k)</span>
                    <span style={{ fontSize: 24, fontWeight: 700, color: ACCENT, fontFamily: MONO, lineHeight: 1 }}>{threshold}</span>
                  </div>
                  <input type="range" min={2} max={totalShares} value={threshold} style={{ width: "100%" }}
                    onChange={e => setThreshold(+e.target.value)} />
                </div>
              </div>
              <div style={{
                display: "inline-flex", alignItems: "center", gap: 7,
                background: ACCENT_SOFT, border: "1px solid #d4e0fc",
                borderRadius: 8, padding: "7px 14px", fontSize: 13, fontWeight: 600, color: ACCENT,
              }}>
                <LockIcon />
                {threshold}-of-{totalShares} scheme
              </div>
              <p style={{ fontSize: 12.5, color: TEXT_SEC, marginTop: 12, lineHeight: 1.6 }}>
                Any {threshold} shareholders can recover the seed phrase. Fewer than {threshold} reveals absolutely nothing.
              </p>
            </div>

            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={() => setStep(1)} style={{
                flex: 1, padding: "13px 0", fontSize: 13, fontWeight: 600,
                border: `1px solid ${BORDER}`, borderRadius: 10, cursor: "pointer",
                background: "#fff", color: TEXT_SEC, transition: "all .2s",
              }}>Back</button>
              <button className="cta" onClick={handleSplit} style={{
                flex: 2, padding: "13px 0", fontSize: 14, fontWeight: 600,
                border: "none", borderRadius: 10, cursor: "pointer",
                background: `linear-gradient(135deg, ${NAVY}, #253560)`,
                color: "#fff", boxShadow: "0 4px 16px rgba(21,32,64,.22)",
                transition: "all .3s", letterSpacing: ".02em",
              }}>
                Generate Shares
              </button>
            </div>
          </div>
        )}

        {/* =================== SPLIT STEP 3 =================== */}
        {mode === "split" && step === 3 && (
          <div className="ap">
            <div style={card}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                <div style={label}>Generated Shares</div>
                <span style={{
                  fontSize: 11, fontWeight: 600, color: ACCENT, background: ACCENT_SOFT,
                  padding: "3px 10px", borderRadius: 6, fontFamily: MONO,
                }}>{threshold}-of-{totalShares}</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {shares.map((s, i) => (
                  <div key={i} className="sr" style={{
                    display: "flex", alignItems: "center", gap: 10,
                    background: "#f8f9fb", border: `1px solid ${BORDER}`, borderRadius: 9,
                    padding: "10px 12px",
                  }}>
                    <span style={{
                      display: "inline-flex", alignItems: "center", justifyContent: "center",
                      minWidth: 26, height: 26, borderRadius: 6, fontSize: 11, fontWeight: 700,
                      background: ACCENT_SOFT, color: ACCENT, fontFamily: MONO, flexShrink: 0,
                    }}>{i + 1}</span>
                    <span style={{
                      flex: 1, fontSize: isMobileForced ? 10.5 : "clamp(10.5px,2.2vw,12px)", fontFamily: MONO,
                      color: TEXT_SEC, wordBreak: "break-all", lineHeight: 1.55, minWidth: 0,
                    }}>{s}</span>
                    <CopyBtn text={s} />
                  </div>
                ))}
              </div>

              <div style={{
                marginTop: 16, padding: "12px 14px", borderRadius: 8,
                background: AMBER_BG, borderLeft: `3px solid ${AMBER_BD}`,
                fontSize: 12.5, color: AMBER_TEXT, lineHeight: 1.65,
              }}>
                <strong>Important:</strong> Write each share down separately and store in different secure locations. Never store all shares together. Verify recovery works before destroying your original phrase.
              </div>
            </div>

            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={resetSplit} style={{
                flex: 1, padding: "13px 0", fontSize: 13, fontWeight: 600,
                border: `1px solid ${BORDER}`, borderRadius: 10, cursor: "pointer",
                background: "#fff", color: TEXT_SEC, transition: "all .2s",
              }}>Start Over</button>
              <button onClick={() => {
                const blob = new Blob([shares.map((s, i) => `Share ${i + 1}: ${s}`).join("\n")], { type: "text/plain" });
                const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
                a.download = `seed-shares-${threshold}of${totalShares}.txt`; a.click();
              }} style={{
                flex: 2, padding: "13px 0", fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
                border: `1px solid ${BORDER}`, borderRadius: 10, cursor: "pointer",
                background: "#fff", color: NAVY, transition: "all .2s",
              }}>
                <DownloadIcon /> Download All Shares
              </button>
            </div>
          </div>
        )}

        {/* =================== COMBINE MODE =================== */}
        {mode === "combine" && (
          <div className="af" style={{ animationDelay: ".1s" }}>
            <div style={card}>
              <div style={label}><PlusIcon /> Enter Shares</div>
              <p style={{ fontSize: 12.5, color: TEXT_SEC, marginBottom: 14, lineHeight: 1.55 }}>
                Paste the hex-encoded shares. You need at least <em>k</em> (the threshold) to recover the original seed phrase.
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {inputShares.map((s, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{
                      display: "inline-flex", alignItems: "center", justifyContent: "center",
                      minWidth: 26, height: 26, borderRadius: 6, fontSize: 11, fontWeight: 700,
                      background: "#f0f2f5", color: TEXT_SEC, fontFamily: MONO, flexShrink: 0,
                    }}>{i + 1}</span>
                    <input style={{ ...inputBase, flex: 1, fontFamily: MONO, fontSize: 13 }}
                      placeholder={`Paste share ${i + 1}...`} value={s}
                      onChange={e => { const n = [...inputShares]; n[i] = e.target.value; setInputShares(n); }} />
                    {inputShares.length > 2 && (
                      <button onClick={() => setInputShares(inputShares.filter((_, idx) => idx !== i))} style={{
                        display: "inline-flex", alignItems: "center", justifyContent: "center",
                        width: 34, height: 34, borderRadius: 8, border: `1px solid ${RED_BD}`,
                        background: RED_BG, color: RED, cursor: "pointer", flexShrink: 0,
                      }}>
                        <TrashIcon />
                      </button>
                    )}
                  </div>
                ))}
              </div>
              <button onClick={() => setInputShares([...inputShares, ""])} style={{
                display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
                width: "100%", padding: "10px 0", marginTop: 10,
                background: "transparent", border: `1.5px dashed #d0d5dd`,
                borderRadius: 9, fontSize: 13, fontWeight: 500, color: TEXT_SEC,
                cursor: "pointer", transition: "all .2s",
              }}>
                <PlusIcon /> Add share
              </button>
            </div>

            <button className="cta" onClick={handleCombine} style={{
              width: "100%", padding: "14px 0", fontSize: 14, fontWeight: 600,
              border: "none", borderRadius: 10, cursor: "pointer",
              background: `linear-gradient(135deg, ${NAVY}, #253560)`,
              color: "#fff", letterSpacing: ".02em",
              boxShadow: "0 4px 16px rgba(21,32,64,.22)",
              transition: "all .3s", marginBottom: 14,
            }}>
              Recover Seed Phrase
            </button>

            {error && (
              <div className="ap" style={{
                background: RED_BG, border: `1px solid ${RED_BD}`, borderRadius: 10,
                padding: "12px 16px", fontSize: 12.5, color: RED, fontWeight: 500, marginBottom: 14,
                display: "flex", alignItems: "flex-start", gap: 8,
              }}>
                <span style={{ flexShrink: 0, marginTop: 1 }}><AlertTri /></span>
                {error}
              </div>
            )}

            {recovered && (
              <div className="ap" style={card}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
                  <div style={{ ...label, color: GREEN, marginBottom: 0 }}><ShieldCheck /> Recovered Seed Phrase</div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button onClick={() => setShowRecovered(!showRecovered)} style={{
                      display: "inline-flex", alignItems: "center", gap: 4,
                      background: "#f4f5f7", border: `1px solid ${BORDER}`,
                      borderRadius: 6, padding: "5px 9px", fontSize: 11, color: TEXT_SEC, cursor: "pointer",
                    }}>
                      {showRecovered ? <EyeOffIcon /> : <EyeIcon />}
                    </button>
                    <CopyBtn text={recovered} label="Copy phrase" />
                  </div>
                </div>
                <div style={{
                  background: GREEN_BG, border: `1px solid ${GREEN_BD}`, borderRadius: 10,
                  padding: "18px 20px", fontSize: 14.5, color: showRecovered ? "#065f46" : TEXT_SEC,
                  lineHeight: 1.7, fontFamily: showRecovered ? MONO : SANS, fontWeight: 500,
                  wordBreak: "break-word",
                  WebkitTextSecurity: showRecovered ? "none" : "disc",
                  letterSpacing: showRecovered ? ".01em" : ".2em",
                }}>
                  {recovered}
                </div>
                <p style={{ fontSize: 12, color: TEXT_SEC, marginTop: 12, lineHeight: 1.6 }}>
                  Verify this matches your original seed phrase. Copy it securely and close this page when done.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ---- Footer ---- */}
        <footer style={{
          textAlign: "center", marginTop: isMobileForced ? 28 : "clamp(28px,5vw,44px)",
          fontSize: 11.5, color: "#9aa5b4", lineHeight: 1.7,
        }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 5, marginBottom: 3 }}>
            <LockIcon />
            Client-side only &middot; Zero data transmission &middot; <code style={{ fontFamily: MONO, fontSize: 10 }}>crypto.getRandomValues()</code>
          </div>
          Shamir's Secret Sharing &middot; GF(2<sup>8</sup>) &middot; BIP-39 compatible
        </footer>
      </div>
    </div>
  );
}
