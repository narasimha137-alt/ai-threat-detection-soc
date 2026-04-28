import streamlit as st
import joblib
import pandas as pd
import numpy as np

# ── Page Config ───────────────────────────────────────
st.set_page_config(
    page_title="AI Threat Detection System",
    page_icon="🛡️",
    layout="wide"
)

# ── Custom CSS + Canvas Animation ─────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&display=swap');

    *, *::before, *::after { box-sizing: border-box; }

    /* ── Base ── */
    html, body, .stApp {
        background: transparent !important;
        color: #c8e6f5;
        font-family: 'Share Tech Mono', monospace;
        overflow-x: hidden;
    }

    /* ── Canvas Background ── */
    #cyber-canvas {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 0;
        pointer-events: none;
    }

    /* Grain overlay */
    #grain-overlay {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 1;
        pointer-events: none;
        opacity: 0.035;
        background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E");
        background-size: 128px 128px;
        animation: grainShift 0.5s steps(1) infinite;
    }
    @keyframes grainShift {
        0%   { background-position: 0 0; }
        25%  { background-position: 64px 32px; }
        50%  { background-position: 32px 64px; }
        75%  { background-position: 96px 16px; }
        100% { background-position: 0 0; }
    }

    /* Cursor glow */
    #cursor-glow {
        position: fixed;
        width: 400px; height: 400px;
        border-radius: 50%;
        pointer-events: none;
        z-index: 2;
        transform: translate(-50%, -50%);
        background: radial-gradient(circle, rgba(0,212,255,0.07) 0%, transparent 70%);
        transition: transform 0.05s linear;
    }

    /* ── Streamlit layout cleanup ── */
    .stApp > header { display: none !important; }
    #MainMenu, footer { display: none !important; }

    .block-container {
        position: relative;
        z-index: 10;
        padding: 2rem 2.5rem 3rem 2.5rem !important;
        max-width: 1400px !important;
    }

    /* ── Header ── */
    .main-title {
        font-family: 'Orbitron', sans-serif;
        text-align: center;
        font-size: clamp(28px, 4vw, 52px);
        font-weight: 900;
        color: #00d4ff;
        text-shadow:
            0 0 10px #00d4ff,
            0 0 30px #00d4ff,
            0 0 80px rgba(0,212,255,0.4);
        padding: 30px 0 8px 0;
        letter-spacing: 6px;
        animation: titlePulse 4s ease-in-out infinite;
    }
    @keyframes titlePulse {
        0%, 100% { text-shadow: 0 0 10px #00d4ff, 0 0 30px #00d4ff, 0 0 80px rgba(0,212,255,0.4); }
        50%       { text-shadow: 0 0 20px #00d4ff, 0 0 60px #00d4ff, 0 0 120px rgba(0,212,255,0.6); }
    }
    .subtitle {
        text-align: center;
        color: #3a6680;
        font-size: 12px;
        margin-bottom: 6px;
        letter-spacing: 4px;
        text-transform: uppercase;
    }
    .status-bar {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 24px;
        font-size: 10px;
        color: #2a5566;
        letter-spacing: 2px;
        margin-bottom: 8px;
    }
    .status-dot {
        display: inline-block;
        width: 6px; height: 6px;
        border-radius: 50%;
        background: #00ff88;
        box-shadow: 0 0 8px #00ff88;
        animation: blink 1.4s ease-in-out infinite;
    }
    @keyframes blink {
        0%,100% { opacity: 1; } 50% { opacity: 0.2; }
    }
    .divider {
        border: none;
        height: 1px;
        background: linear-gradient(to right, transparent, #00d4ff66, #00d4ff, #00d4ff66, transparent);
        margin: 8px 0 28px 0;
        position: relative;
    }

    /* ── Glass panels ── */
    .glass-panel {
        background: rgba(5, 15, 30, 0.72);
        backdrop-filter: blur(16px) saturate(180%);
        -webkit-backdrop-filter: blur(16px) saturate(180%);
        border: 1px solid rgba(0, 212, 255, 0.18);
        border-radius: 16px;
        padding: 28px;
        position: relative;
        overflow: hidden;
        transition: border-color 0.3s ease, box-shadow 0.3s ease, transform 0.3s ease;
    }
    .glass-panel::before {
        content: '';
        position: absolute;
        top: 0; left: -100%;
        width: 100%; height: 1px;
        background: linear-gradient(to right, transparent, #00d4ff, transparent);
        animation: scanLine 6s linear infinite;
    }
    @keyframes scanLine {
        0%   { left: -100%; }
        100% { left: 200%; }
    }
    .glass-panel:hover {
        border-color: rgba(0, 212, 255, 0.5);
        box-shadow: 0 0 40px rgba(0, 212, 255, 0.08), inset 0 0 40px rgba(0, 212, 255, 0.02);
        transform: translateY(-2px);
    }

    /* ── Section Headers ── */
    .section-header {
        font-family: 'Orbitron', sans-serif;
        color: #00d4ff;
        font-size: 12px;
        font-weight: 700;
        border-bottom: 1px solid rgba(0,212,255,0.25);
        padding-bottom: 12px;
        margin-bottom: 22px;
        letter-spacing: 4px;
        text-transform: uppercase;
        text-shadow: 0 0 12px rgba(0,212,255,0.6);
    }

    /* ── Metrics ── */
    [data-testid="metric-container"] {
        background: rgba(5, 15, 30, 0.8) !important;
        border: 1px solid rgba(0, 212, 255, 0.2) !important;
        border-radius: 12px !important;
        padding: 18px !important;
        text-align: center !important;
        position: relative;
        overflow: hidden;
        transition: all 0.3s ease;
    }
    [data-testid="metric-container"]:hover {
        border-color: rgba(0,212,255,0.6) !important;
        box-shadow: 0 0 30px rgba(0,212,255,0.12) !important;
        transform: translateY(-3px);
    }
    [data-testid="stMetricValue"] {
        font-family: 'Orbitron', sans-serif !important;
        color: #00d4ff !important;
        font-size: 20px !important;
        font-weight: 700 !important;
        text-shadow: 0 0 15px rgba(0,212,255,0.8) !important;
    }
    [data-testid="stMetricLabel"] {
        color: #3a6680 !important;
        font-size: 10px !important;
        letter-spacing: 2px !important;
        text-transform: uppercase !important;
    }

    /* ── Threat Result Boxes ── */
    .threat-high {
        background: linear-gradient(135deg, rgba(40,0,15,0.9), rgba(20,0,8,0.95));
        border: 2px solid #ff0044;
        border-radius: 16px;
        padding: 40px 30px;
        text-align: center;
        font-family: 'Orbitron', sans-serif;
        font-size: clamp(22px, 3vw, 36px);
        font-weight: 900;
        color: #ff2255;
        text-shadow: 0 0 20px #ff0044, 0 0 40px rgba(255,0,68,0.5);
        margin: 10px 0;
        box-shadow: 0 0 60px rgba(255,0,68,0.15), inset 0 0 40px rgba(255,0,68,0.05);
        animation: threatPulseHigh 1.5s ease-in-out infinite;
    }
    @keyframes threatPulseHigh {
        0%,100% { box-shadow: 0 0 40px rgba(255,0,68,0.15), inset 0 0 40px rgba(255,0,68,0.05); }
        50%      { box-shadow: 0 0 80px rgba(255,0,68,0.3),  inset 0 0 60px rgba(255,0,68,0.1); }
    }
    .threat-medium {
        background: linear-gradient(135deg, rgba(28,18,0,0.9), rgba(18,12,0,0.95));
        border: 2px solid #ffaa00;
        border-radius: 16px;
        padding: 40px 30px;
        text-align: center;
        font-family: 'Orbitron', sans-serif;
        font-size: clamp(22px, 3vw, 36px);
        font-weight: 900;
        color: #ffcc00;
        text-shadow: 0 0 20px #ffaa00, 0 0 40px rgba(255,170,0,0.5);
        margin: 10px 0;
        box-shadow: 0 0 60px rgba(255,170,0,0.12), inset 0 0 40px rgba(255,170,0,0.04);
        animation: threatPulseMed 2s ease-in-out infinite;
    }
    @keyframes threatPulseMed {
        0%,100% { box-shadow: 0 0 40px rgba(255,170,0,0.12); }
        50%      { box-shadow: 0 0 70px rgba(255,170,0,0.25); }
    }
    .threat-low {
        background: linear-gradient(135deg, rgba(0,25,10,0.9), rgba(0,18,10,0.95));
        border: 2px solid #00ff88;
        border-radius: 16px;
        padding: 40px 30px;
        text-align: center;
        font-family: 'Orbitron', sans-serif;
        font-size: clamp(22px, 3vw, 36px);
        font-weight: 900;
        color: #00ff88;
        text-shadow: 0 0 20px #00ff88, 0 0 40px rgba(0,255,136,0.5);
        margin: 10px 0;
        box-shadow: 0 0 60px rgba(0,255,136,0.12), inset 0 0 40px rgba(0,255,136,0.04);
        animation: threatPulseLow 3s ease-in-out infinite;
    }
    @keyframes threatPulseLow {
        0%,100% { box-shadow: 0 0 40px rgba(0,255,136,0.12); }
        50%      { box-shadow: 0 0 70px rgba(0,255,136,0.22); }
    }

    /* ── Button ── */
    .stButton > button {
        width: 100%;
        background: linear-gradient(135deg, rgba(0,40,80,0.9), rgba(0,100,160,0.7));
        color: #00d4ff !important;
        font-family: 'Orbitron', sans-serif !important;
        font-size: 13px !important;
        font-weight: 700 !important;
        border: 1px solid rgba(0,212,255,0.5) !important;
        border-radius: 10px !important;
        padding: 18px !important;
        cursor: pointer !important;
        text-transform: uppercase !important;
        letter-spacing: 4px !important;
        margin-top: 12px !important;
        transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
        position: relative;
        overflow: hidden;
    }
    .stButton > button::after {
        content: '';
        position: absolute;
        top: 50%; left: 50%;
        width: 0; height: 0;
        background: rgba(0,212,255,0.2);
        border-radius: 50%;
        transform: translate(-50%, -50%);
        transition: width 0.5s ease, height 0.5s ease, opacity 0.5s ease;
        opacity: 0;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, rgba(0,100,160,0.9), rgba(0,180,220,0.5)) !important;
        border-color: #00d4ff !important;
        box-shadow: 0 0 30px rgba(0,212,255,0.35), 0 0 60px rgba(0,212,255,0.15) !important;
        transform: translateY(-3px) scale(1.01) !important;
        color: #ffffff !important;
    }
    .stButton > button:active {
        transform: translateY(0) scale(0.99) !important;
    }

    /* ── Form Inputs ── */
    div[data-testid="stSelectbox"] label,
    div[data-testid="stSlider"] label,
    div[data-testid="stNumberInput"] label {
        font-family: 'Share Tech Mono', monospace !important;
        color: #3a7a99 !important;
        font-size: 10px !important;
        letter-spacing: 2px !important;
        text-transform: uppercase !important;
    }
    .stSelectbox > div > div,
    div[data-baseweb="select"] > div {
        background-color: rgba(5,15,30,0.85) !important;
        border: 1px solid rgba(0,212,255,0.25) !important;
        border-radius: 8px !important;
        color: #c8e6f5 !important;
        transition: border-color 0.3s ease, box-shadow 0.3s ease !important;
    }
    .stSelectbox > div > div:hover,
    div[data-baseweb="select"] > div:hover {
        border-color: rgba(0,212,255,0.6) !important;
        box-shadow: 0 0 15px rgba(0,212,255,0.12) !important;
    }
    div[data-testid="stNumberInput"] input {
        background-color: rgba(5,15,30,0.85) !important;
        border: 1px solid rgba(0,212,255,0.25) !important;
        border-radius: 8px !important;
        color: #c8e6f5 !important;
        font-family: 'Share Tech Mono', monospace !important;
    }
    div[data-testid="stNumberInput"] input:focus {
        border-color: rgba(0,212,255,0.7) !important;
        box-shadow: 0 0 20px rgba(0,212,255,0.2) !important;
    }

    /* Sliders */
    .stSlider [data-baseweb="slider"] [data-testid="stTickBar"] { display: none; }
    .stSlider div[role="slider"] {
        background: #00d4ff !important;
        box-shadow: 0 0 12px #00d4ff !important;
    }

    /* Progress bars */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #003366, #00d4ff) !important;
        border-radius: 4px !important;
        box-shadow: 0 0 10px rgba(0,212,255,0.4) !important;
    }
    .stProgress > div > div {
        background: rgba(0,212,255,0.08) !important;
        border-radius: 4px !important;
    }

    /* ── Confidence Label ── */
    .confidence-label {
        font-family: 'Orbitron', sans-serif;
        font-size: 11px;
        color: #3a7a99;
        margin-bottom: 10px;
        letter-spacing: 3px;
    }

    /* ── Info / Alert boxes ── */
    .stAlert {
        background: rgba(5,15,30,0.8) !important;
        border-radius: 10px !important;
        backdrop-filter: blur(8px) !important;
    }

    /* ── HUD corner decorations ── */
    .hud-corners {
        position: relative;
        padding: 4px;
    }
    .hud-corners::before, .hud-corners::after {
        content: '';
        position: absolute;
        width: 14px; height: 14px;
        border-color: #00d4ff;
        border-style: solid;
        opacity: 0.6;
    }
    .hud-corners::before { top: 0; left: 0; border-width: 2px 0 0 2px; }
    .hud-corners::after  { bottom: 0; right: 0; border-width: 0 2px 2px 0; }

    /* ── Holographic badge ── */
    .holo-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(0,212,255,0.06);
        border: 1px solid rgba(0,212,255,0.3);
        border-radius: 6px;
        padding: 5px 12px;
        font-size: 10px;
        letter-spacing: 2px;
        color: #5599bb;
        animation: holoBadge 3s ease-in-out infinite;
    }
    @keyframes holoBadge {
        0%,100% { border-color: rgba(0,212,255,0.3); box-shadow: none; }
        50%      { border-color: rgba(0,212,255,0.7); box-shadow: 0 0 12px rgba(0,212,255,0.2); }
    }

    /* ── Footer ── */
    .footer {
        text-align: center;
        color: #1e3344;
        font-family: 'Share Tech Mono', monospace;
        font-size: 10px;
        letter-spacing: 3px;
        margin-top: 40px;
        padding: 20px;
        border-top: 1px solid rgba(0,212,255,0.08);
    }

    /* ── Glitch Text ── */
    .glitch {
        position: relative;
        animation: glitch 8s infinite;
    }
    @keyframes glitch {
        0%,94%,100%  { transform: translate(0); filter: none; }
        95%  { transform: translate(-2px, 1px); filter: hue-rotate(90deg); }
        96%  { transform: translate(2px, -1px); filter: hue-rotate(-90deg); }
        97%  { transform: translate(-1px, 2px); }
        98%  { transform: translate(0); filter: none; }
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: #060c14; }
    ::-webkit-scrollbar-thumb { background: #00d4ff44; border-radius: 2px; }
    ::-webkit-scrollbar-thumb:hover { background: #00d4ff88; }
</style>

<!-- Live background canvas -->
<canvas id="cyber-canvas"></canvas>
<div id="grain-overlay"></div>
<div id="cursor-glow"></div>

<script>
(function() {
    const canvas = document.getElementById('cyber-canvas');
    const ctx = canvas.getContext('2d');
    const glow = document.getElementById('cursor-glow');

    let W, H, mouse = { x: -999, y: -999 };
    let t = 0;

    function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    // Cursor tracking
    window.addEventListener('mousemove', e => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
        glow.style.left = e.clientX + 'px';
        glow.style.top  = e.clientY + 'px';
    });

    // ── Particles ──
    const PARTICLE_COUNT = 55;
    const particles = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles.push({
            x: Math.random() * 2000,
            y: Math.random() * 2000,
            vx: (Math.random() - 0.5) * 0.35,
            vy: (Math.random() - 0.5) * 0.35,
            r: Math.random() * 1.8 + 0.4,
            alpha: Math.random() * 0.6 + 0.1,
            alphaDir: (Math.random() > 0.5 ? 1 : -1) * 0.004
        });
    }

    // ── Pulse rings ──
    const pulses = [];
    function addPulse() {
        pulses.push({
            x: Math.random() * 2000,
            y: Math.random() * 2000,
            r: 0,
            maxR: Math.random() * 180 + 80,
            alpha: 0.6,
            speed: Math.random() * 1.2 + 0.5,
            color: Math.random() > 0.7 ? '#00ff88' : '#00d4ff'
        });
    }
    for (let i = 0; i < 5; i++) addPulse();
    setInterval(addPulse, 2200);

    // ── Data streams ──
    const STREAM_COUNT = 18;
    const streams = [];
    for (let i = 0; i < STREAM_COUNT; i++) {
        streams.push({
            x: Math.random() * 2000,
            y: Math.random() * 2000,
            chars: Array.from({length: Math.floor(Math.random()*10+4)}, () =>
                String.fromCharCode(0x30a0 + Math.random()*96 | 0)),
            speed: Math.random() * 0.8 + 0.3,
            alpha: Math.random() * 0.12 + 0.03,
            size: Math.floor(Math.random()*6+8)
        });
    }

    // ── Node network ──
    const NODES = 22;
    const nodes = [];
    for (let i = 0; i < NODES; i++) {
        nodes.push({
            x: Math.random() * 2000,
            y: Math.random() * 2000,
            vx: (Math.random()-0.5)*0.2,
            vy: (Math.random()-0.5)*0.2,
            r: Math.random()*3+1.5
        });
    }

    // ── Scanbeam ──
    let scanX = 0, scanY = 0, scanDirX = 1, scanDirY = 1;

    // ── Glitch ──
    let glitchTimer = 0;
    let glitching = false;

    function draw() {
        t += 0.008;

        // Parallax offset based on mouse
        const px = (mouse.x / (W||1) - 0.5) * 18;
        const py = (mouse.y / (H||1) - 0.5) * 18;

        ctx.clearRect(0, 0, W, H);

        // ── Deep background ──
        const bg = ctx.createRadialGradient(W/2, H/2, 0, W/2, H/2, Math.max(W,H)*0.75);
        bg.addColorStop(0,   'rgba(2,8,20,1)');
        bg.addColorStop(0.5, 'rgba(1,5,14,1)');
        bg.addColorStop(1,   'rgba(0,2,8,1)');
        ctx.fillStyle = bg;
        ctx.fillRect(0, 0, W, H);

        // Mouse reactive inner glow
        if (mouse.x > 0) {
            const mg = ctx.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, 320);
            mg.addColorStop(0,   'rgba(0,212,255,0.04)');
            mg.addColorStop(1,   'rgba(0,212,255,0)');
            ctx.fillStyle = mg;
            ctx.fillRect(0, 0, W, H);
        }

        // ── Animated Grid ──
        const gridOffX = ((t * 22) % 60) + px * 0.3;
        const gridOffY = ((t * 12) % 60) + py * 0.3;
        ctx.save();
        ctx.globalAlpha = 0.055;
        ctx.strokeStyle = '#00d4ff';
        ctx.lineWidth = 0.5;
        for (let x = -60 + (gridOffX % 60); x < W + 60; x += 60) {
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
        }
        for (let y = -60 + (gridOffY % 60); y < H + 60; y += 60) {
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
        }
        ctx.restore();

        // ── Node network ──
        ctx.save();
        nodes.forEach(n => {
            n.x += n.vx + px * 0.002;
            n.y += n.vy + py * 0.002;
            if (n.x < -50) n.x = W + 50;
            if (n.x > W+50) n.x = -50;
            if (n.y < -50) n.y = H + 50;
            if (n.y > H+50) n.y = -50;
        });
        nodes.forEach((a, i) => {
            nodes.forEach((b, j) => {
                if (j <= i) return;
                const dx = a.x - b.x, dy = a.y - b.y;
                const d = Math.sqrt(dx*dx + dy*dy);
                if (d < 180) {
                    const alpha = (1 - d/180) * 0.22;
                    ctx.strokeStyle = `rgba(0,212,255,${alpha})`;
                    ctx.lineWidth = 0.5;
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                    ctx.stroke();
                }
            });
        });
        nodes.forEach(n => {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
            ctx.fillStyle = 'rgba(0,212,255,0.7)';
            ctx.shadowColor = '#00d4ff';
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
        });
        ctx.restore();

        // ── Particles ──
        ctx.save();
        particles.forEach(p => {
            p.x += p.vx + px * 0.001;
            p.y += p.vy + py * 0.001;
            if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
            if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
            p.alpha += p.alphaDir;
            if (p.alpha > 0.8 || p.alpha < 0.05) p.alphaDir *= -1;

            // React slightly to mouse
            const mdx = p.x - mouse.x, mdy = p.y - mouse.y;
            const md = Math.sqrt(mdx*mdx + mdy*mdy);
            if (md < 120) {
                p.x += (mdx/md)*0.5;
                p.y += (mdy/md)*0.5;
            }

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
            ctx.fillStyle = `rgba(0,212,255,${p.alpha})`;
            ctx.shadowColor = '#00d4ff';
            ctx.shadowBlur = 6;
            ctx.fill();
            ctx.shadowBlur = 0;
        });
        ctx.restore();

        // ── Pulse rings ──
        ctx.save();
        for (let i = pulses.length - 1; i >= 0; i--) {
            const p = pulses[i];
            p.r += p.speed;
            p.alpha -= 0.007;
            if (p.r >= p.maxR || p.alpha <= 0) {
                pulses.splice(i, 1); continue;
            }
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
            ctx.strokeStyle = p.color.replace(')', `,${p.alpha})`).replace('rgb(','rgba(');
            // Just use hex with global alpha
            ctx.globalAlpha = p.alpha;
            ctx.strokeStyle = p.color;
            ctx.lineWidth = 1.2;
            ctx.shadowColor = p.color;
            ctx.shadowBlur = 10;
            ctx.stroke();
            ctx.shadowBlur = 0;
        }
        ctx.globalAlpha = 1;
        ctx.restore();

        // ── Data streams ──
        ctx.save();
        streams.forEach(s => {
            s.y += s.speed;
            if (s.y > H + 200) { s.y = -200; s.x = Math.random() * W; }
            ctx.font = `${s.size}px "Share Tech Mono", monospace`;
            s.chars.forEach((c, i) => {
                const alpha = (1 - i/s.chars.length) * s.alpha;
                ctx.fillStyle = `rgba(0,212,255,${alpha})`;
                if (i === 0) {
                    ctx.fillStyle = `rgba(180,240,255,${s.alpha * 2})`;
                    ctx.shadowColor = '#00d4ff'; ctx.shadowBlur = 8;
                }
                ctx.fillText(c, s.x, s.y - i * (s.size + 2));
                ctx.shadowBlur = 0;
            });
            // Randomly mutate chars
            if (Math.random() < 0.04) {
                const idx = Math.floor(Math.random() * s.chars.length);
                s.chars[idx] = String.fromCharCode(0x30a0 + Math.random()*96 | 0);
            }
        });
        ctx.restore();

        // ── Scan beam (horizontal) ──
        scanX += scanDirX * 1.8;
        if (scanX > W + 200 || scanX < -200) scanDirX *= -1;
        ctx.save();
        const hBeam = ctx.createLinearGradient(scanX - 200, 0, scanX + 200, 0);
        hBeam.addColorStop(0,   'rgba(0,212,255,0)');
        hBeam.addColorStop(0.5, 'rgba(0,212,255,0.06)');
        hBeam.addColorStop(1,   'rgba(0,212,255,0)');
        ctx.fillStyle = hBeam;
        ctx.fillRect(scanX - 200, 0, 400, H);
        // Leading line
        ctx.strokeStyle = 'rgba(0,212,255,0.35)';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(scanX, 0); ctx.lineTo(scanX, H); ctx.stroke();
        ctx.restore();

        // ── Scan beam (vertical) ──
        scanY += scanDirY * 0.7;
        if (scanY > H + 200 || scanY < -200) scanDirY *= -1;
        ctx.save();
        const vBeam = ctx.createLinearGradient(0, scanY - 120, 0, scanY + 120);
        vBeam.addColorStop(0,   'rgba(0,212,255,0)');
        vBeam.addColorStop(0.5, 'rgba(0,212,255,0.03)');
        vBeam.addColorStop(1,   'rgba(0,212,255,0)');
        ctx.fillStyle = vBeam;
        ctx.fillRect(0, scanY - 120, W, 240);
        ctx.restore();

        // ── Glitch effect ──
        glitchTimer++;
        if (!glitching && glitchTimer > 400 + Math.random() * 600) {
            glitching = true; glitchTimer = 0;
        }
        if (glitching) {
            const slices = Math.floor(Math.random() * 4) + 1;
            for (let s = 0; s < slices; s++) {
                const sy = Math.random() * H;
                const sh = Math.random() * 12 + 2;
                const offset = (Math.random() - 0.5) * 30;
                ctx.save();
                ctx.globalAlpha = 0.18;
                const id = ctx.getImageData(0, sy, W, sh);
                ctx.putImageData(id, offset, sy);
                ctx.restore();
            }
            if (Math.random() < 0.25) glitching = false;
        }

        requestAnimationFrame(draw);
    }

    draw();
})();
</script>
""", unsafe_allow_html=True)

# ── Load Model ────────────────────────────────────────
model     = joblib.load("threat_model.pkl")
scaler    = joblib.load("scaler.pkl")
le_target = joblib.load("label_encoder.pkl")

# ── Header ────────────────────────────────────────────
st.markdown('<div class="main-title glitch">🛡️ AI THREAT DETECTION SYSTEM</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Defence Intelligence Dashboard — Jarvis Neural Core v4.2</div>', unsafe_allow_html=True)
st.markdown("""
<div class="status-bar">
    <span><span class="status-dot"></span> SYSTEM ONLINE</span>
    <span>|</span>
    <span>NEURAL CORE: ACTIVE</span>
    <span>|</span>
    <span>THREAT SCAN: LIVE</span>
    <span>|</span>
    <span><span class="status-dot" style="background:#00d4ff;box-shadow:0 0 8px #00d4ff;animation-delay:.7s"></span> ALL SENSORS NOMINAL</span>
</div>
""", unsafe_allow_html=True)
st.markdown('<hr class="divider">', unsafe_allow_html=True)

# ── Top Metrics ───────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
with m1: st.metric("🎯 Model",    "Random Forest")
with m2: st.metric("✅ Accuracy", "99%+")
with m3: st.metric("📊 Features", "41")
with m4: st.metric("🔍 Classes",  "LOW / MED / HIGH")

st.markdown("<br>", unsafe_allow_html=True)

# ── Holographic badges ────────────────────────────────
st.markdown("""
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;">
    <span class="holo-badge">⬡ NSL-KDD DATASET</span>
    <span class="holo-badge">⬡ RF CLASSIFIER</span>
    <span class="holo-badge">⬡ REAL-TIME ANALYSIS</span>
    <span class="holo-badge">⬡ 41-FEATURE VECTOR</span>
    <span class="holo-badge">⬡ CLASSIFICATION ENGINE</span>
</div>
""", unsafe_allow_html=True)

# ── Main Layout ───────────────────────────────────────
left, right = st.columns([1, 1], gap="large")

with left:
    with st.container():
        st.markdown('<div class="glass-panel hud-corners">', unsafe_allow_html=True)
        st.markdown('<div class="section-header">⚙ Input Parameters</div>', unsafe_allow_html=True)

        protocol = st.selectbox("Protocol Type",   ["TCP", "UDP", "ICMP"])
        service  = st.selectbox("Service Type",    ["HTTP", "FTP", "SMTP", "SSH", "DNS", "Other"])
        flag     = st.selectbox("Connection Flag", ["SF (Normal)", "S0 (No Response)", "REJ (Rejected)", "RSTO", "SH"])

        col1, col2 = st.columns(2)
        with col1:
            duration      = st.slider("Duration (sec)", 0, 100, 0)
            failed_logins = st.slider("Failed Logins",  0, 10,  0)
            src_bytes     = st.number_input("Source Bytes", 0, 100000, 0)
        with col2:
            dst_bytes  = st.number_input("Dest Bytes",       0, 100000, 0)
            logged_in  = st.selectbox("Logged In",           [0, 1])
            root_shell = st.selectbox("Root Shell Access",   [0, 1])

        rerror_rate = st.slider("Error Rate", 0.0, 1.0, 0.0, 0.1)

        st.markdown("<br>", unsafe_allow_html=True)
        predict_btn = st.button("🔍  ANALYZE THREAT LEVEL")
        st.markdown('</div>', unsafe_allow_html=True)

with right:
    with st.container():
        st.markdown('<div class="glass-panel hud-corners">', unsafe_allow_html=True)
        st.markdown('<div class="section-header">📊 Detection Result</div>', unsafe_allow_html=True)

        if predict_btn:
            proto_map   = {"TCP": 2, "UDP": 1, "ICMP": 0}
            service_map = {"HTTP": 10, "FTP": 4, "SMTP": 18, "SSH": 20, "DNS": 3, "Other": 0}
            flag_map    = {"SF (Normal)": 5, "S0 (No Response)": 4, "REJ (Rejected)": 3, "RSTO": 2, "SH": 1}

            sample = pd.DataFrame([{
                "duration": duration,
                "protocol_type": proto_map[protocol],
                "service": service_map[service],
                "flag": flag_map[flag],
                "src_bytes": src_bytes,
                "dst_bytes": dst_bytes,
                "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
                "num_failed_logins": failed_logins,
                "logged_in": logged_in,
                "num_compromised": 0,
                "root_shell": root_shell,
                "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
                "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
                "is_host_login": 0, "is_guest_login": 0,
                "count": 1, "srv_count": 1,
                "serror_rate": 0.0, "srv_serror_rate": 0.0,
                "rerror_rate": rerror_rate, "srv_rerror_rate": rerror_rate,
                "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0, "dst_host_count": 1,
                "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0,
                "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
                "dst_host_srv_serror_rate": 0.0,
                "dst_host_rerror_rate": rerror_rate,
                "dst_host_srv_rerror_rate": rerror_rate
            }])

            pred   = model.predict(scaler.transform(sample))
            proba  = model.predict_proba(scaler.transform(sample))[0]
            threat = le_target.inverse_transform(pred)[0]

            if threat == "HIGH":
                st.markdown('<div class="threat-high">🔴 HIGH THREAT DETECTED ⚠️</div>', unsafe_allow_html=True)
                st.error("🚨 CRITICAL ALERT: Immediate action required!")
            elif threat == "MEDIUM":
                st.markdown('<div class="threat-medium">🟡 MEDIUM THREAT LEVEL</div>', unsafe_allow_html=True)
                st.warning("⚠️ WARNING: Unusual activity detected. Monitor closely.")
            else:
                st.markdown('<div class="threat-low">🟢 SYSTEM SECURE — LOW RISK</div>', unsafe_allow_html=True)
                st.success("✅ All systems nominal. No threats detected.")

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown('<div class="confidence-label">📈 CONFIDENCE SCORES</div>', unsafe_allow_html=True)
            classes = le_target.classes_
            icons   = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
            for i, cls in enumerate(classes):
                st.progress(float(proba[i]), text=f"{icons.get(cls,'⚪')} {cls}: {proba[i]*100:.1f}%")

        else:
            st.info("👈 Set parameters on the left and click **ANALYZE THREAT LEVEL**")
            st.markdown("<br>", unsafe_allow_html=True)
            st.image("confusion_matrix.png",
                     caption="Confusion Matrix — Model Performance",
                     use_container_width=True)

        st.markdown('</div>', unsafe_allow_html=True)

# ── Bottom Graphs ─────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<hr class="divider">', unsafe_allow_html=True)

st.markdown("""
<div class="glass-panel" style="margin-bottom:24px;">
    <div class="section-header">📈 Model Performance Analytics</div>
""", unsafe_allow_html=True)

g1, g2 = st.columns(2, gap="large")
with g1:
    st.image("feature_importance.png",
             caption="Top 15 Features by Importance",
             use_container_width=True)
with g2:
    st.image("model_comparison.png",
             caption="Random Forest vs Logistic Regression",
             use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────
st.markdown("""
<div class="footer">
    🛡️ AI THREAT DETECTION SYSTEM &nbsp;·&nbsp;
    Powered by Random Forest ML &nbsp;·&nbsp;
    NSL-KDD Dataset &nbsp;·&nbsp;
    Accuracy: 99%+ &nbsp;·&nbsp;
    Jarvis Neural Core v4.2
</div>
""", unsafe_allow_html=True)