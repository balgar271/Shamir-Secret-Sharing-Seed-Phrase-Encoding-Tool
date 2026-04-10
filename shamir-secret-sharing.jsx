import { useState, useCallback, useEffect } from "react";

// ---- Finite Field Arithmetic (GF(256)) ----
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x = x ^ (x << 1) ^ (x >= 128 ? 0x11b : 0);
    x &= 0xff;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
function gfMul(a, b) { if (a === 0 || b === 0) return 0; return EXP[LOG[a] + LOG[b]]; }
function gfDiv(a, b) { if (b === 0) throw new Error("Division by zero"); if (a === 0) return 0; return EXP[(LOG[a] + 255 - LOG[b]) % 255]; }
function evalPoly(coeffs, x) { let r = 0; for (let i = coeffs.length - 1; i >= 0; i--) r = gfMul(r, x) ^ coeffs[i]; return r; }
function lagrangeInterpolate(points) {
  let secret = 0;
  for (let i = 0; i < points.length; i++) {
    let num = 1, den = 1;
    for (let j = 0; j < points.length; j++) { if (i === j) continue; num = gfMul(num, points[j][0]); den = gfMul(den, points[i][0] ^ points[j][0]); }
    secret ^= gfMul(points[i][1], gfDiv(num, den));
  }
  return secret;
}
function splitSecret(secretBytes, n, k) {
  const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, data: new Uint8Array(secretBytes.length) }));
  for (let b = 0; b < secretBytes.length; b++) {
    const coeffs = new Uint8Array(k);
    coeffs[0] = secretBytes[b];
    for (let c = 1; c < k; c++) coeffs[c] = Math.floor(Math.random() * 256);
    for (let i = 0; i < n; i++) shares[i].data[b] = evalPoly(coeffs, shares[i].x);
  }
  return shares;
}
function combineShares(shares) {
  if (shares.length === 0) return new Uint8Array(0);
  const len = shares[0].data.length;
  const result = new Uint8Array(len);
  for (let b = 0; b < len; b++) { const pts = shares.map(s => [s.x, s.data[b]]); result[b] = lagrangeInterpolate(pts); }
  return result;
}
function shareToHex(share) {
  return share.x.toString(16).padStart(2, "0") + Array.from(share.data).map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToShare(hex) {
  const x = parseInt(hex.slice(0, 2), 16);
  const data = new Uint8Array((hex.length - 2) / 2);
  for (let i = 0; i < data.length; i++) data[i] = parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16);
  return { x, data };
}

// ---- Icons ----
const ShieldIcon = ({ size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);
const SplitIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M16 3h5v5"/><path d="M8 3H3v5"/><path d="M12 22v-8.3a4 4 0 0 1 1.172-2.872L21 3"/>
    <path d="M12 22v-8.3a4 4 0 0 0-1.172-2.872L3 3"/>
  </svg>
);
const MergeIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M8 21h8"/><path d="M12 21v-8"/><path d="m17 8-5 5-5-5"/>
    <path d="M3 3h5v5"/><path d="M16 3h5v5"/>
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

// ---- Copy button ----
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  return (
    <button onClick={handleCopy} style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      background: copied ? "#ecfdf5" : "#f4f5f7", border: "1px solid " + (copied ? "#a7f3d0" : "#dfe3e8"),
      borderRadius: 6, padding: "5px 10px", fontSize: 12, fontWeight: 500,
      color: copied ? "#047857" : "#5a6577", cursor: "pointer", transition: "all 0.2s",
      fontFamily: "inherit", whiteSpace: "nowrap", flexShrink: 0,
    }}>
      {copied ? <CheckIcon /> : <CopyIcon />}
      <span>{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

// ---- Tokens ----
const NAVY = "#152040";
const ACCENT = "#2761e6";
const ACCENT_SOFT = "#eef3ff";
const BORDER = "#e4e8ee";
const TEXT_PRI = "#1c2a3d";
const TEXT_SEC = "#6b7a8d";
const CARD_BG = "rgba(255,255,255,0.88)";
const MONO = `'JetBrains Mono', 'SF Mono', 'Consolas', 'Menlo', monospace`;

export default function ShamirTool() {
  const [mode, setMode] = useState("split");
  const [secret, setSecret] = useState("");
  const [totalShares, setTotalShares] = useState(5);
  const [threshold, setThreshold] = useState(3);
  const [shares, setShares] = useState([]);
  const [inputShares, setInputShares] = useState(["", "", ""]);
  const [recovered, setRecovered] = useState(null);
  const [error, setError] = useState("");

  const handleSplit = useCallback(() => {
    if (!secret) return;
    const bytes = new TextEncoder().encode(secret);
    setShares(splitSecret(bytes, totalShares, threshold).map(s => shareToHex(s)));
  }, [secret, totalShares, threshold]);

  const handleCombine = useCallback(() => {
    setError(""); setRecovered(null);
    try {
      const parsed = inputShares.filter(s => s.trim()).map(s => hexToShare(s.trim()));
      if (parsed.length < 2) { setError("Provide at least 2 shares to recover the secret."); return; }
      setRecovered(new TextDecoder().decode(combineShares(parsed)));
    } catch { setError("Invalid share format. Please double-check your inputs."); }
  }, [inputShares]);

  const css = `
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap');
    *, *::before, *::after { box-sizing: border-box; margin: 0; }
    body { margin: 0; }
    input:focus, textarea:focus { outline: none; border-color: ${ACCENT} !important; box-shadow: 0 0 0 3px rgba(39,97,230,0.1) !important; }
    input::placeholder, textarea::placeholder { color: #b0b8c4; }
    button { font-family: 'DM Sans', system-ui, sans-serif; }
    button:active { transform: scale(0.98); }
    input[type=range] { -webkit-appearance: none; appearance: none; height: 5px; background: linear-gradient(90deg, ${ACCENT}, #93b4f5); border-radius: 99px; outline: none; opacity: 0.7; transition: opacity 0.2s; }
    input[type=range]:hover { opacity: 1; }
    input[type=range]::-webkit-slider-thumb { -webkit-appearance: none; width: 22px; height: 22px; border-radius: 50%; background: #fff; border: 2.5px solid ${ACCENT}; box-shadow: 0 1px 6px rgba(0,0,0,0.12); cursor: pointer; transition: box-shadow 0.2s; }
    input[type=range]::-webkit-slider-thumb:hover { box-shadow: 0 2px 10px rgba(39,97,230,0.3); }
    input[type=range]::-moz-range-thumb { width: 22px; height: 22px; border-radius: 50%; background: #fff; border: 2.5px solid ${ACCENT}; box-shadow: 0 1px 6px rgba(0,0,0,0.12); cursor: pointer; }
    @keyframes fadeUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes popIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
    .anim-fade { animation: fadeUp 0.5s cubic-bezier(0.22,1,0.36,1) both; }
    .anim-pop { animation: popIn 0.35s cubic-bezier(0.22,1,0.36,1) both; }
    .share-row { transition: background 0.15s, box-shadow 0.15s; }
    .share-row:hover { background: #f6f8fb !important; box-shadow: 0 1px 4px rgba(0,0,0,0.04) !important; }
    .cta-btn:hover { box-shadow: 0 6px 20px rgba(21,32,64,0.3) !important; transform: translateY(-1px); }
    @media (max-width: 520px) { .param-grid { grid-template-columns: 1fr !important; } }
  `;

  const inputBase = {
    width: "100%", background: "#fafbfc", border: `1.5px solid ${BORDER}`, borderRadius: 8,
    padding: "12px 14px", color: TEXT_PRI, fontSize: 14, fontFamily: "'DM Sans', system-ui, sans-serif",
    transition: "border-color 0.2s, box-shadow 0.2s",
  };

  const card = {
    background: CARD_BG, border: `1px solid ${BORDER}`, borderRadius: 14,
    padding: "clamp(16px, 4vw, 24px)", marginBottom: 14,
    backdropFilter: "blur(16px)", boxShadow: "0 1px 3px rgba(0,0,0,0.03), 0 0 0 1px rgba(255,255,255,0.6) inset",
  };

  const sectionLabel = {
    display: "flex", alignItems: "center", gap: 7, fontSize: 11.5, fontWeight: 600,
    color: NAVY, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 12,
  };

  return (
    <div style={{
      minHeight: "100vh", fontFamily: "'DM Sans', system-ui, sans-serif", color: TEXT_PRI,
      background: "linear-gradient(170deg, #f0f3f8 0%, #f8f9fb 40%, #ffffff 100%)",
      position: "relative",
    }}>
      <style>{css}</style>

      {/* Subtle dot pattern */}
      <svg style={{ position: "fixed", inset: 0, width: "100%", height: "100%", zIndex: 0, pointerEvents: "none", opacity: 0.35 }}>
        <defs><pattern id="bg-dots" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="0.6" fill="#b4bcc8"/>
        </pattern></defs>
        <rect width="100%" height="100%" fill="url(#bg-dots)"/>
      </svg>

      <div style={{
        position: "relative", zIndex: 1, maxWidth: 600, margin: "0 auto",
        padding: "clamp(28px, 6vw, 56px) clamp(16px, 5vw, 28px) 48px",
      }}>
        {/* Header */}
        <header className="anim-fade" style={{ textAlign: "center", marginBottom: "clamp(28px, 5vw, 40px)" }}>
          <div style={{
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            width: 56, height: 56, borderRadius: 16, marginBottom: 18,
            background: `linear-gradient(145deg, ${NAVY}, #253560)`,
            boxShadow: `0 8px 24px rgba(21,32,64,0.22), 0 0 0 1px rgba(255,255,255,0.08) inset`,
          }}>
            <span style={{ color: "#fff", display: "flex" }}><ShieldIcon size={26}/></span>
          </div>
          <h1 style={{
            fontSize: "clamp(21px, 4.5vw, 27px)", fontWeight: 700, color: NAVY,
            letterSpacing: "-0.025em", margin: "0 0 8px", lineHeight: 1.25,
          }}>
            Shamir Secret Sharing
          </h1>
          <p style={{ fontSize: "clamp(13px, 2.5vw, 14.5px)", color: TEXT_SEC, lineHeight: 1.55, maxWidth: 420, margin: "0 auto" }}>
            Split a secret into <em>n</em> shares using polynomial interpolation over GF(256).
            Any <em>k</em> shares reconstruct it — fewer reveal nothing.
          </p>
        </header>

        {/* Tabs */}
        <div className="anim-fade" style={{
          display: "flex", gap: 4, padding: 4, marginBottom: "clamp(20px, 4vw, 28px)",
          background: "#eaecf1", borderRadius: 11, animationDelay: "0.06s",
        }}>
          {[
            { key: "split", label: "Split Secret", icon: <SplitIcon /> },
            { key: "combine", label: "Combine Shares", icon: <MergeIcon /> },
          ].map(t => (
            <button key={t.key} onClick={() => { setMode(t.key); setError(""); setRecovered(null); }} style={{
              flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 7,
              padding: "11px 0", fontSize: 13, fontWeight: 600,
              border: "none", borderRadius: 9, cursor: "pointer",
              background: mode === t.key ? "#fff" : "transparent",
              color: mode === t.key ? NAVY : TEXT_SEC,
              boxShadow: mode === t.key ? "0 1px 5px rgba(0,0,0,0.07), 0 0 0 1px rgba(0,0,0,0.03)" : "none",
              transition: "all 0.25s ease",
            }}>
              {t.icon}<span>{t.label}</span>
            </button>
          ))}
        </div>

        {/* ===================== SPLIT MODE ===================== */}
        {mode === "split" && (
          <div className="anim-fade" style={{ animationDelay: "0.1s" }}>
            {/* Secret */}
            <div style={card}>
              <div style={sectionLabel}><KeyIcon /> Your Secret</div>
              <textarea
                style={{ ...inputBase, minHeight: 88, resize: "vertical", lineHeight: 1.6 }}
                placeholder="Enter the text you want to protect..."
                value={secret}
                onChange={e => setSecret(e.target.value)}
              />
            </div>

            {/* Parameters */}
            <div style={card}>
              <div style={sectionLabel}><span style={{ fontSize: 14 }}>&#9881;</span> Scheme Parameters</div>
              <div className="param-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "clamp(14px, 3vw, 20px)", marginBottom: 16 }}>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
                    <span style={{ fontSize: 13, color: TEXT_SEC, fontWeight: 500 }}>Total shares (n)</span>
                    <span style={{ fontSize: 24, fontWeight: 700, color: ACCENT, fontFamily: MONO, lineHeight: 1 }}>{totalShares}</span>
                  </div>
                  <input type="range" min={2} max={255} value={totalShares} style={{ width: "100%" }}
                    onChange={e => { const v = +e.target.value; setTotalShares(v); if (threshold > v) setThreshold(v); }} />
                </div>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
                    <span style={{ fontSize: 13, color: TEXT_SEC, fontWeight: 500 }}>Threshold (k)</span>
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
            </div>

            {/* Generate */}
            <button className="cta-btn" onClick={handleSplit} disabled={!secret} style={{
              width: "100%", padding: "15px 0", fontSize: 14, fontWeight: 600,
              border: "none", borderRadius: 11, cursor: secret ? "pointer" : "not-allowed",
              background: secret ? `linear-gradient(135deg, ${NAVY} 0%, #253560 100%)` : "#ced4dc",
              color: "#fff", letterSpacing: "0.02em",
              boxShadow: secret ? "0 4px 16px rgba(21,32,64,0.22)" : "none",
              transition: "all 0.3s ease", marginBottom: 14,
            }}>
              Generate Shares
            </button>

            {/* Output */}
            {shares.length > 0 && (
              <div className="anim-pop" style={card}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                  <div style={sectionLabel}>Generated Shares</div>
                  <span style={{
                    fontSize: 11, fontWeight: 600, color: ACCENT, background: ACCENT_SOFT,
                    padding: "3px 9px", borderRadius: 5, fontFamily: MONO,
                  }}>{shares.length}</span>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {shares.map((s, i) => (
                    <div key={i} className="share-row" style={{
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
                        flex: 1, fontSize: "clamp(11px, 2.2vw, 12.5px)", fontFamily: MONO, fontWeight: 400,
                        color: TEXT_SEC, wordBreak: "break-all", lineHeight: 1.55, minWidth: 0,
                      }}>{s}</span>
                      <CopyButton text={s} />
                    </div>
                  ))}
                </div>
                <p style={{
                  fontSize: 12.5, color: TEXT_SEC, marginTop: 14, lineHeight: 1.6,
                  padding: "10px 14px", background: "#f4f6f8", borderRadius: 8, borderLeft: `3px solid ${BORDER}`,
                }}>
                  Distribute each share to a different party. Each hex string encodes the evaluation point and the polynomial values.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ===================== COMBINE MODE ===================== */}
        {mode === "combine" && (
          <div className="anim-fade" style={{ animationDelay: "0.1s" }}>
            <div style={card}>
              <div style={sectionLabel}><MergeIcon /> Enter Shares</div>
              <p style={{ fontSize: 13, color: TEXT_SEC, marginBottom: 16, lineHeight: 1.55 }}>
                Paste the hex-encoded shares you received. You need at least <em>k</em> (the threshold) to recover the original secret.
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {inputShares.map((s, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{
                      display: "inline-flex", alignItems: "center", justifyContent: "center",
                      minWidth: 26, height: 26, borderRadius: 6, fontSize: 11, fontWeight: 700,
                      background: "#f0f2f5", color: TEXT_SEC, fontFamily: MONO, flexShrink: 0,
                    }}>{i + 1}</span>
                    <input
                      style={{ ...inputBase, flex: 1, fontFamily: MONO, fontSize: 13 }}
                      placeholder={`Paste share ${i + 1}...`}
                      value={s}
                      onChange={e => { const n = [...inputShares]; n[i] = e.target.value; setInputShares(n); }}
                    />
                    {inputShares.length > 2 && (
                      <button onClick={() => setInputShares(inputShares.filter((_, idx) => idx !== i))} style={{
                        display: "inline-flex", alignItems: "center", justifyContent: "center",
                        width: 34, height: 34, borderRadius: 8, border: "1px solid #fce4e4",
                        background: "#fff5f5", color: "#dc3545", cursor: "pointer", flexShrink: 0,
                        transition: "all 0.15s",
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
                cursor: "pointer", transition: "all 0.2s",
              }}>
                <PlusIcon /> Add another share
              </button>
            </div>

            <button className="cta-btn" onClick={handleCombine} style={{
              width: "100%", padding: "15px 0", fontSize: 14, fontWeight: 600,
              border: "none", borderRadius: 11, cursor: "pointer",
              background: `linear-gradient(135deg, ${NAVY} 0%, #253560 100%)`,
              color: "#fff", letterSpacing: "0.02em",
              boxShadow: "0 4px 16px rgba(21,32,64,0.22)",
              transition: "all 0.3s ease", marginBottom: 14,
            }}>
              Recover Secret
            </button>

            {error && (
              <div className="anim-pop" style={{
                background: "#fff5f5", border: "1px solid #fce4e4", borderRadius: 10,
                padding: "12px 16px", fontSize: 13, color: "#c53030", fontWeight: 500, marginBottom: 14,
              }}>{error}</div>
            )}

            {recovered !== null && (
              <div className="anim-pop" style={card}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                  <div style={sectionLabel}><CheckIcon /> Recovered Secret</div>
                  <CopyButton text={recovered} />
                </div>
                <div style={{
                  background: "linear-gradient(135deg, #f0fdf4, #ecfdf5)", border: "1px solid #bbf7d0",
                  borderRadius: 10, padding: "18px 20px",
                  fontSize: "clamp(14px, 3vw, 16px)", color: "#14532d", lineHeight: 1.65,
                  fontWeight: 500, wordBreak: "break-word",
                }}>
                  {recovered}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Footer */}
        <footer style={{
          textAlign: "center", marginTop: "clamp(28px, 5vw, 44px)",
          fontSize: 11.5, color: "#9aa5b4", lineHeight: 1.7, letterSpacing: "0.01em",
        }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 5, marginBottom: 3 }}>
            <LockIcon /> Client-side only — nothing leaves your browser
          </div>
          <br/>
          Shamir's Secret Sharing &middot; GF(2<sup>8</sup>) &middot; Up to 255 shares
        </footer>
      </div>
    </div>
  );
}
