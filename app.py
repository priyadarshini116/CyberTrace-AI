from __future__ import annotations

import json
import tempfile
from html import escape
from pathlib import Path

import streamlit as st

from copilot.attack_simulator import generate_attack
from copilot.investigation import investigate_incident
from copilot.reporting import render_markdown_report

from tests.evaluation import evaluate_dataset
from tests.test_cases import (
    get_attack_cases,
    get_benign_cases,
)
from tests.rule_evaluation import run_rule_evaluation


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="CyberTrace AI · Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# DESIGN SYSTEM  (single stylesheet)
# =========================================================

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700;800&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root{
  --bg:#060914; --panel:#0d1226; --panel2:#111833;
  --ink:#eaf0ff; --soft:#b4bfdc; --mut:#7f8cad;
  --line:rgba(140,155,255,.14); --line2:rgba(140,155,255,.26);
  --cy:#3de1ff; --vi:#8b7bff; --pk:#ff4d8d; --gr:#35e0a1;
  --am:#ffc14d; --or:#ff8a3d; --rd:#ff4d6d;
  --mono:'JetBrains Mono',monospace; --disp:'Sora',sans-serif;
}

/* ---------- canvas ---------- */
html, body, .stApp{font-family:'Inter',sans-serif;color:var(--ink)}
.stApp{
  background:
    radial-gradient(900px 520px at 88% -8%, rgba(139,123,255,.22), transparent 60%),
    radial-gradient(760px 480px at -4% 18%, rgba(61,225,255,.13), transparent 60%),
    radial-gradient(700px 500px at 60% 110%, rgba(255,77,141,.08), transparent 60%),
    var(--bg);
}
.stApp::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(140,155,255,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(140,155,255,.045) 1px, transparent 1px);
  background-size:46px 46px;
  -webkit-mask-image:radial-gradient(ellipse at 50% 0%, #000 0%, transparent 72%);
          mask-image:radial-gradient(ellipse at 50% 0%, #000 0%, transparent 72%);
}
#MainMenu, footer{visibility:hidden}
header[data-testid="stHeader"]{background:transparent}
.block-container{max-width:1440px;padding:1.6rem 2.2rem 4rem;position:relative;z-index:1}

h1,h2,h3,h4{font-family:var(--disp)!important;color:var(--ink)!important;letter-spacing:-.025em}
h2,h3{font-weight:700!important}
p,li,label,.stMarkdown{color:var(--soft)}
[data-testid="stCaptionContainer"]{color:var(--mut)}
hr{border-color:var(--line)!important;margin:1.6rem 0!important}

/* ---------- sidebar ---------- */
section[data-testid="stSidebar"]{
  background:linear-gradient(180deg,#0b1024 0%,#070b1a 100%);
  border-right:1px solid var(--line);
}
section[data-testid="stSidebar"]>div{padding-top:1.2rem}
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p{color:#cdd6f0!important;font-size:13px}
section[data-testid="stSidebar"] h3{font-size:12px!important;color:var(--mut)!important;font-weight:600!important;letter-spacing:.02em;margin:.4rem 0 .2rem}
section[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"]{gap:4px}
section[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"]>label{
  padding:9px 12px;border:1px solid transparent;border-radius:10px;transition:background .15s,border-color .15s;
}
section[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"]>label:hover{background:rgba(139,123,255,.07)}
section[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"]>label:has(input:checked){
  background:linear-gradient(100deg,rgba(139,123,255,.20),rgba(61,225,255,.09));
  border-color:rgba(139,123,255,.38);
}
section[data-testid="stSidebar"] [data-testid="stFileUploader"] section{
  background:rgba(13,18,38,.8);border:1px dashed var(--line2);border-radius:12px;
}

.ct-brand{display:flex;align-items:center;gap:12px;padding:4px 2px 14px}
.ct-logo{
  width:40px;height:40px;border-radius:12px;display:grid;place-items:center;
  font:700 14px var(--disp);color:#06101c;
  background:linear-gradient(135deg,var(--cy),var(--vi));
  box-shadow:0 0 24px rgba(61,225,255,.35);
}
.ct-brand b{display:block;font:700 15px var(--disp);color:var(--ink);letter-spacing:-.01em}
.ct-brand small{display:block;margin-top:2px;font-size:11px;color:var(--mut)}
.ct-live{
  display:flex;align-items:center;gap:8px;margin:2px 0 6px;padding:8px 12px;border-radius:10px;
  background:rgba(53,224,161,.07);border:1px solid rgba(53,224,161,.22);color:#8bf0c9;font-size:12px;
}
.ct-dot{width:7px;height:7px;border-radius:50%;background:var(--gr);box-shadow:0 0 10px var(--gr);animation:ctpulse 2s infinite}
@keyframes ctpulse{50%{opacity:.35}}

/* ---------- sidebar threat radar ---------- */
.ct-side{margin-top:14px;padding:14px;border-radius:16px;border:1px solid var(--line2);
  background:linear-gradient(160deg,rgba(23,32,66,.85),rgba(8,12,28,.9));box-shadow:0 12px 34px rgba(0,0,0,.4)}
.ct-side-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;font:600 12px var(--disp);color:var(--ink)}
.ct-side-h span{display:flex;align-items:center;gap:8px}
.ct-side-h em{font:600 11px var(--mono);font-style:normal;color:var(--acc)}
.ct-radar{position:relative;width:100%;aspect-ratio:1;border-radius:50%;overflow:hidden;
  border:1px solid rgba(61,225,255,.4);
  background:
    linear-gradient(rgba(61,225,255,.18),rgba(61,225,255,.18)) center/1px 100% no-repeat,
    linear-gradient(rgba(61,225,255,.18),rgba(61,225,255,.18)) center/100% 1px no-repeat,
    repeating-radial-gradient(circle,transparent 0 26px,rgba(61,225,255,.16) 26px 27px),
    radial-gradient(circle,rgba(61,225,255,.12),transparent 70%);
  box-shadow:0 0 36px rgba(61,225,255,.18), inset 0 0 30px rgba(61,225,255,.08)}
.ct-radar::before{content:"";position:absolute;inset:0;border-radius:50%;
  background:conic-gradient(from 0deg,rgba(61,225,255,.55),rgba(139,123,255,.18) 18%,transparent 30%);
  animation:ctspin 4s linear infinite}
@keyframes ctspin{to{transform:rotate(360deg)}}
.ct-blip{position:absolute;width:9px;height:9px;border-radius:50%;background:var(--acc);
  box-shadow:0 0 14px var(--acc),0 0 0 4px color-mix(in srgb,var(--acc) 25%,transparent);animation:ctpulse 1.8s infinite}
.ct-core{position:absolute;left:50%;top:50%;width:8px;height:8px;margin:-4px;border-radius:50%;background:var(--cy);box-shadow:0 0 12px var(--cy)}
.ct-side-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:14px}
.ct-side-grid div{padding:9px 6px;border-radius:10px;text-align:center;background:rgba(5,8,20,.6);border:1px solid var(--line)}
.ct-side-grid b{display:block;font:700 17px var(--disp);color:var(--ink)}
.ct-side-grid span{font-size:10.5px;color:var(--mut)}

/* ---------- hero ---------- */
.ct-hero{
  position:relative;overflow:hidden;display:flex;align-items:center;justify-content:space-between;gap:30px;
  padding:34px 38px;margin:0 0 26px;border-radius:24px;
  border:1px solid var(--line2);
  background:
    radial-gradient(520px 260px at 90% 0%, rgba(139,123,255,.30), transparent 70%),
    radial-gradient(420px 240px at 0% 100%, rgba(61,225,255,.14), transparent 70%),
    linear-gradient(135deg,#121a3a,#0b1126 70%);
  box-shadow:0 30px 80px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.06);
}
.ct-hero::after{
  content:"";position:absolute;left:0;right:0;top:-40%;height:40%;pointer-events:none;
  background:linear-gradient(180deg,transparent,rgba(61,225,255,.10),transparent);
  animation:ctscan 6s linear infinite;
}
@keyframes ctscan{to{top:120%}}
.ct-hero-copy{position:relative;z-index:1;max-width:760px}
.ct-pill{
  display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;
  background:rgba(61,225,255,.08);border:1px solid rgba(61,225,255,.28);color:#9cefff;font:500 12px var(--mono);
}
.ct-hero h1{margin:16px 0 10px;font-size:clamp(34px,4.6vw,58px);line-height:1.04;font-weight:800;letter-spacing:-.045em}
.ct-grad{background:linear-gradient(95deg,var(--cy),var(--vi) 55%,var(--pk));-webkit-background-clip:text;background-clip:text;color:transparent}
.ct-hero p{margin:0;max-width:600px;color:var(--soft);font-size:15px;line-height:1.7}
.ct-chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}
.ct-chip{
  padding:6px 11px;border-radius:8px;border:1px solid var(--line2);background:rgba(8,12,28,.55);
  color:#c5d0ef;font:500 11.5px var(--mono);
}
.ct-hero-side{position:relative;z-index:1;flex:0 0 auto}

/* ---------- cards ---------- */
.ct-card{
  padding:20px 22px;border-radius:18px;border:1px solid var(--line);height:100%;
  background:linear-gradient(150deg,rgba(23,32,66,.78),rgba(12,18,40,.78));
  box-shadow:0 14px 40px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.04);
  backdrop-filter:blur(14px);
}
.ct-card h3{margin:0 0 6px;font-size:16px}
.ct-card p{margin:0;font-size:13px;line-height:1.7;color:var(--mut)}
.ct-ico{
  width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-size:20px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(61,225,255,.16),rgba(139,123,255,.18));border:1px solid var(--line2);
}
.ct-kpi{
  position:relative;overflow:hidden;padding:18px 20px;border-radius:16px;border:1px solid var(--line);
  background:linear-gradient(150deg,rgba(23,32,66,.8),rgba(12,18,40,.8));
}
.ct-kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--acc,var(--cy));box-shadow:0 0 18px var(--acc,var(--cy))}
.ct-kpi span{display:block;font-size:12px;color:var(--mut);font-weight:500}
.ct-kpi b{display:block;margin-top:6px;font:700 30px var(--disp);letter-spacing:-.03em;color:var(--ink)}
.ct-kpi small{display:block;margin-top:4px;font-size:12px;color:var(--mut)}

.ct-section{display:flex;align-items:baseline;justify-content:space-between;margin:26px 0 12px}
.ct-section h2{margin:0;font-size:20px}
.ct-section span{font-size:12.5px;color:var(--mut)}

/* ---------- pipeline ---------- */
.ct-pipe{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:8px 0 6px}
.ct-step{position:relative;padding:16px;border-radius:14px;border:1px solid var(--line);background:rgba(13,18,38,.7)}
.ct-step i{
  display:grid;place-items:center;width:26px;height:26px;border-radius:8px;margin-bottom:10px;font:600 12px var(--mono);
  font-style:normal;color:#06101c;background:linear-gradient(135deg,var(--cy),var(--vi));
}
.ct-step b{display:block;font:600 13.5px var(--disp);color:var(--ink)}
.ct-step small{display:block;margin-top:4px;font-size:12px;line-height:1.5;color:var(--mut)}

/* ---------- severity ---------- */
.ct-sev{display:inline-flex;align-items:center;gap:6px;padding:4px 11px;border-radius:999px;font:600 11.5px var(--mono);border:1px solid}
.ct-sev::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.sev-critical{color:var(--rd);border-color:rgba(255,77,109,.4);background:rgba(255,77,109,.10)}
.sev-high{color:var(--or);border-color:rgba(255,138,61,.4);background:rgba(255,138,61,.10)}
.sev-medium{color:var(--am);border-color:rgba(255,193,77,.4);background:rgba(255,193,77,.10)}
.sev-low{color:var(--gr);border-color:rgba(53,224,161,.4);background:rgba(53,224,161,.10)}
.sev-info{color:var(--cy);border-color:rgba(61,225,255,.4);background:rgba(61,225,255,.10)}

/* ---------- findings ---------- */
.ct-find{
  position:relative;margin:0 0 14px;padding:20px 22px 20px 26px;border-radius:16px;border:1px solid var(--line);
  background:linear-gradient(150deg,rgba(23,32,66,.78),rgba(12,18,40,.78));overflow:hidden;
}
.ct-find::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--acc);box-shadow:0 0 22px var(--acc)}
.ct-find-top{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}
.ct-find-title{font:600 17px var(--disp);color:var(--ink);letter-spacing:-.02em}
.ct-find-title code{margin-right:10px;padding:3px 8px;border-radius:7px;font:500 12px var(--mono);color:#a9b6ff;background:rgba(139,123,255,.14)}
.ct-meta{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.ct-tag{padding:5px 10px;border-radius:8px;font:500 12px var(--mono);color:#c9d3f2;background:rgba(8,12,28,.6);border:1px solid var(--line)}
.ct-tag b{color:var(--cy);font-weight:600}
.ct-evidence{
  margin-top:6px;padding:13px 15px;border-radius:11px;white-space:pre-wrap;word-break:break-word;
  font:400 12.5px/1.7 var(--mono);color:#b9c6e8;background:rgba(5,8,20,.65);border:1px solid var(--line);
}
.ct-conf{display:flex;align-items:center;gap:10px;font:500 12px var(--mono);color:var(--mut)}
.ct-bar{position:relative;flex:1;min-width:90px;height:7px;border-radius:99px;background:rgba(140,155,255,.12);overflow:hidden}
.ct-bar>i{position:absolute;inset:0 auto 0 0;border-radius:99px;background:linear-gradient(90deg,var(--cy),var(--vi))}

/* ---------- ring gauge ---------- */
.ct-ring{position:relative}
.ct-ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ct-ring-bg{fill:none;stroke:rgba(140,155,255,.14);stroke-width:9}
.ct-ring-fg{fill:none;stroke-width:9;stroke-linecap:round;animation:ctring 1.4s cubic-bezier(.2,.8,.2,1) both;filter:drop-shadow(0 0 7px currentColor)}
@keyframes ctring{from{stroke-dashoffset:var(--c)}}
.ct-ring-txt{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ct-ring-txt b{font:700 28px var(--disp);color:var(--ink);letter-spacing:-.03em}
.ct-ring-txt span{margin-top:2px;font-size:11px;color:var(--mut)}

/* ---------- confusion matrix ---------- */
.ct-cm{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.ct-cm div{padding:20px;border-radius:14px;border:1px solid var(--line)}
.ct-cm span{display:block;font-size:12px;color:var(--soft)}
.ct-cm b{display:block;margin-top:4px;font:700 34px var(--disp);letter-spacing:-.03em}
.cm-tp{background:rgba(53,224,161,.09);border-color:rgba(53,224,161,.3)!important}.cm-tp b{color:var(--gr)}
.cm-tn{background:rgba(61,225,255,.08);border-color:rgba(61,225,255,.3)!important}.cm-tn b{color:var(--cy)}
.cm-fp{background:rgba(255,193,77,.08);border-color:rgba(255,193,77,.3)!important}.cm-fp b{color:var(--am)}
.cm-fn{background:rgba(255,77,109,.09);border-color:rgba(255,77,109,.3)!important}.cm-fn b{color:var(--rd)}

/* ---------- action / reasoning ---------- */
.ct-action{display:flex;gap:14px;align-items:flex-start;margin-bottom:10px;padding:14px 16px;border-radius:13px;border:1px solid var(--line);background:rgba(13,18,38,.7)}
.ct-action i{flex:0 0 auto;display:grid;place-items:center;width:28px;height:28px;border-radius:9px;font:600 12px var(--mono);font-style:normal;color:#06101c;background:linear-gradient(135deg,var(--cy),var(--vi))}
.ct-action span{font-size:14px;line-height:1.6;color:#d4dcf3}
.ct-reason{padding:11px 14px;margin-bottom:8px;border-left:2px solid var(--vi);background:rgba(139,123,255,.06);border-radius:0 10px 10px 0;font-size:13.5px;line-height:1.6;color:#cbd5f0}
.ct-summary{padding:22px 24px;border-radius:16px;border:1px solid var(--line2);background:linear-gradient(135deg,rgba(139,123,255,.12),rgba(61,225,255,.05));font-size:15px;line-height:1.8;color:#dbe3f8}

/* ---------- factor bars (simulator) ---------- */
.ct-factor{display:grid;grid-template-columns:170px 1fr 70px;gap:14px;align-items:center;margin-bottom:12px;font-size:13px;color:var(--soft)}
.ct-factor small{display:block;color:var(--mut);font-size:11.5px}
.ct-factor em{font:600 13px var(--mono);font-style:normal;color:var(--ink);text-align:right}

/* ---------- streamlit widgets ---------- */
.stButton>button,.stDownloadButton>button{
  min-height:44px;border-radius:12px;border:1px solid rgba(139,123,255,.45);color:#fff;font-weight:600;
  background:linear-gradient(105deg,#6d5df0,#2aa8d6);transition:transform .15s,box-shadow .15s;
}
.stButton>button:hover,.stDownloadButton>button:hover{transform:translateY(-1px);box-shadow:0 10px 28px rgba(109,93,240,.4);border-color:var(--cy);color:#fff}
.stTextInput input,.stTextArea textarea,.stNumberInput input,[data-baseweb="input"] input,[data-baseweb="select"]>div{
  background:#0a1022!important;border:1px solid var(--line2)!important;border-radius:10px!important;
  color:var(--ink)!important;-webkit-text-fill-color:var(--ink)!important;
}
[data-baseweb="select"] *{color:var(--ink)!important}
[data-baseweb="popover"],[data-baseweb="menu"]{background:#111833!important;border:1px solid var(--line2)!important}
div[data-testid="stMetric"]{padding:16px 18px;border-radius:14px;border:1px solid var(--line);background:rgba(13,18,38,.7)}
div[data-testid="stMetricLabel"] p{color:var(--mut)!important}
div[data-testid="stMetricValue"]{color:var(--cy)!important;font-family:var(--disp)}
div[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:14px;overflow:hidden}
div[data-testid="stExpander"]{border:1px solid var(--line);border-radius:14px;background:rgba(13,18,38,.6)}
div[data-testid="stAlert"]{border:1px solid var(--line2);border-radius:12px;background:#0f1630!important}
div[data-testid="stAlert"] p{color:var(--ink)!important}
.stProgress>div>div>div{background:linear-gradient(90deg,var(--cy),var(--vi),var(--pk))}
[data-testid="stSlider"] [role="slider"]{background:var(--cy)!important;box-shadow:0 0 12px var(--cy)}

div[data-testid="stTabs"] [role="tablist"]{gap:4px;border-bottom:1px solid var(--line)}
div[data-testid="stTabs"] button{font:600 13px 'Inter',sans-serif;color:var(--mut);padding:10px 16px}
div[data-testid="stTabs"] button[aria-selected="true"]{color:var(--ink)}
div[data-testid="stTabs"] [data-baseweb="tab-highlight"]{background:linear-gradient(90deg,var(--cy),var(--vi));height:3px;border-radius:3px}

a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid var(--cy)!important;outline-offset:2px}

@media(max-width:900px){
  .ct-hero{flex-direction:column;align-items:flex-start;padding:26px 22px}
  .ct-pipe{grid-template-columns:1fr 1fr}
  .ct-factor{grid-template-columns:1fr}
  .block-container{padding:1rem 1rem 3rem}
}
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
}
</style>
"""

st.markdown(CSS, unsafe_allow_html=True)


# =========================================================
# UI HELPERS
# =========================================================

def esc(value) -> str:
    """HTML-escape any value (event data is untrusted)."""
    return escape(str(value))


def h(markup: str) -> None:
    """Render raw HTML. Lines are flattened so Markdown never treats indented HTML as code."""
    st.markdown(
        "".join(line.strip() for line in markup.strip().splitlines()),
        unsafe_allow_html=True,
    )


def sev_class(severity) -> str:
    key = str(severity).strip().lower()
    return f"sev-{key}" if key in {"critical", "high", "medium", "low"} else "sev-info"


SEV_COLOR = {
    "critical": "var(--rd)",
    "high": "var(--or)",
    "medium": "var(--am)",
    "low": "var(--gr)",
}


def sev_color(severity) -> str:
    return SEV_COLOR.get(str(severity).strip().lower(), "var(--cy)")


def sev_badge(severity) -> str:
    return f'<span class="ct-sev {sev_class(severity)}">{esc(severity)}</span>'


def ring(value, label: str, color: str = "var(--cy)", suffix: str = "%", size: int = 140) -> str:
    v = max(0.0, min(100.0, float(value)))
    c = 2 * 3.14159265 * 52
    off = c * (1 - v / 100)
    return (
        f'<div class="ct-ring" style="width:{size}px;height:{size}px;color:{color}">'
        f'<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" class="ct-ring-bg"/>'
        f'<circle cx="60" cy="60" r="52" class="ct-ring-fg" '
        f'style="stroke:{color};stroke-dasharray:{c:.1f};stroke-dashoffset:{off:.1f};--c:{c:.1f}"/></svg>'
        f'<div class="ct-ring-txt"><b>{v:.0f}{suffix}</b><span>{esc(label)}</span></div></div>'
    )


def kpi(label: str, value, sub: str = "", accent: str = "var(--cy)") -> str:
    return (
        f'<div class="ct-kpi" style="--acc:{accent}"><span>{esc(label)}</span>'
        f'<b>{esc(value)}</b><small>{esc(sub)}</small></div>'
    )


def hero(pill: str, title_html: str, text: str, chips=(), side_html: str = "") -> None:
    chip_html = "".join(f'<span class="ct-chip">{esc(c)}</span>' for c in chips)
    h(
        f'<div class="ct-hero"><div class="ct-hero-copy">'
        f'<span class="ct-pill"><i class="ct-dot"></i>{esc(pill)}</span>'
        f'<h1>{title_html}</h1><p>{esc(text)}</p>'
        f'<div class="ct-chips">{chip_html}</div></div>'
        f'<div class="ct-hero-side">{side_html}</div></div>'
    )


def section(title: str, hint: str = "") -> None:
    h(f'<div class="ct-section"><h2>{esc(title)}</h2><span>{esc(hint)}</span></div>')


def feature_card(icon: str, title: str, text: str) -> str:
    return (
        f'<div class="ct-card"><div class="ct-ico">{icon}</div>'
        f'<h3>{esc(title)}</h3><p>{esc(text)}</p></div>'
    )


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:
    h(
        '<div class="ct-brand"><div class="ct-logo">CT</div>'
        '<div><b>CyberTrace AI</b><small>Security operations platform</small></div></div>'
    )

page = st.sidebar.radio(
    "Workspace",
    [
        "Incident Investigation",
        "Detection Evaluation",
        "Cyber Impact Simulator",
    ],
    label_visibility="collapsed",
)

# Safe defaults so every page can run on its own
run_investigation = False
uploaded_file = None
use_llm = False
scenario = "Brute Force"
username = ""
source_ip = ""
input_mode = "Event File"

if page == "Incident Investigation":

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Input mode")
    input_mode = st.sidebar.radio(
        "Input mode",
        ["Event File", "Attack Simulator"],
        label_visibility="collapsed",
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Analyst engine")
    ai_mode = st.sidebar.radio(
        "Choose analysis mode",
        ["Gemini LLM", "Deterministic / No API"],
        index=0,
        label_visibility="collapsed",
    )
    use_llm = ai_mode == "Gemini LLM"

    if use_llm:
        st.sidebar.success("Gemini analyst active")
        st.sidebar.caption(
            "AI analyst powered by Google Gemini. Detection and MITRE mapping "
            "remain deterministic and evidence-grounded."
        )
    else:
        st.sidebar.info("Offline mode")
        st.sidebar.caption(
            "No external API calls. Analysis uses the built-in deterministic SOC analyst."
        )

    st.sidebar.markdown("---")

    if input_mode == "Attack Simulator":
        st.sidebar.markdown("### Attack simulator")
        scenario = st.sidebar.selectbox(
            "Attack scenario",
            ["Brute Force", "PowerShell", "Credential Access", "Lateral Movement", "Full APT Chain"],
        )
        username = st.sidebar.text_input("Username", value="j.smith")
        source_ip = st.sidebar.text_input("Source IP", value="10.10.10.50")
        st.sidebar.caption("Generates synthetic security telemetry. No real attack is performed.")
        run_investigation = st.sidebar.button(
            "Run investigation", type="primary", use_container_width=True
        )
    else:
        st.sidebar.markdown("### Event file")
        uploaded_file = st.sidebar.file_uploader("Upload security event JSON", type=["json"])
        run_investigation = uploaded_file is not None

radar_slot = st.sidebar.empty()

BLIPS = [(20, 58), (56, 22), (68, 66), (34, 30), (46, 74), (78, 42)]


def paint_radar(res) -> None:
    """Live threat radar: one pulsing blip per detection, coloured by incident severity."""
    if res:
        summ = res.get("summary", {})
        sev = summ.get("severity", "-")
        n_events = summ.get("event_count", 0)
        n_find = summ.get("finding_count", len(res.get("findings", [])))
        status, acc = str(sev), sev_color(sev)
    else:
        n_events, n_find, status, acc = 0, 0, "Standing by", "var(--gr)"
    blips = "".join(
        f'<i class="ct-blip" style="top:{t}%;left:{l}%;animation-delay:{i * .35:.2f}s"></i>'
        for i, (t, l) in enumerate(BLIPS[: min(int(n_find or 0), len(BLIPS))])
    )
    with radar_slot.container():
        h(
            f'<div class="ct-side" style="--acc:{acc}">'
            f'<div class="ct-side-h"><span><i class="ct-dot"></i>Threat radar</span><em>{esc(status)}</em></div>'
            f'<div class="ct-radar" style="--acc:{acc}"><i class="ct-core"></i>{blips}</div>'
            f'<div class="ct-side-grid"><div><b>{esc(n_events)}</b><span>events</span></div>'
            f'<div><b>{esc(n_find)}</b><span>threats</span></div>'
            f'<div><b>{"ON" if use_llm else "OFF"}</b><span>Gemini</span></div></div></div>'
        )


paint_radar(st.session_state.get("investigation_result"))

# =========================================================
# PAGE: CYBER IMPACT SIMULATOR
# =========================================================

if page == "Cyber Impact Simulator":

    LEVELS = {"Low": 20, "Medium": 45, "High": 75, "Critical": 100}
    EXPOSURE = {"Internal": 25, "Restricted": 60, "Internet-facing": 100}
    DATA = {"Public": 10, "Internal": 35, "Confidential": 70, "Sensitive": 100}

    placeholder = st.container()

    section("Configure a hypothetical incident", "Move the sliders. The score updates instantly.")
    left, right = st.columns(2, gap="large")

    with left:
        incident_type = st.selectbox(
            "Incident scenario",
            [
                "Account compromise",
                "Ransomware disruption",
                "Data exfiltration",
                "Malware infection",
                "Service availability attack",
            ],
        )
        severity_label = st.select_slider("Technical severity", options=list(LEVELS), value="High")
        asset_label = st.select_slider("Asset business criticality", options=list(LEVELS), value="High")

    with right:
        exposure_label = st.select_slider(
            "Exposure level", options=list(EXPOSURE), value="Internet-facing"
        )
        data_label = st.select_slider("Data sensitivity", options=list(DATA), value="Confidential")
        recovery_hours = st.slider("Estimated recovery time (hours)", 1, 72, 12)

    # Weighted score, each factor scaled to 0-100. Formula is intentionally visible.
    recovery_points = min(100, round((recovery_hours / 72) * 100))
    factors = [
        ("Technical severity", severity_label, LEVELS[severity_label], 0.30),
        ("Asset criticality", asset_label, LEVELS[asset_label], 0.25),
        ("Exposure", exposure_label, EXPOSURE[exposure_label], 0.20),
        ("Data sensitivity", data_label, DATA[data_label], 0.15),
        ("Recovery time", f"{recovery_hours} hours", recovery_points, 0.10),
    ]
    impact_score = round(sum(points * weight for _, _, points, weight in factors))

    if impact_score < 25:
        impact_band = "Low"
    elif impact_score < 50:
        impact_band = "Moderate"
    elif impact_score < 75:
        impact_band = "High"
    else:
        impact_band = "Critical"

    band_color = {
        "Low": "var(--gr)",
        "Moderate": "var(--am)",
        "High": "var(--or)",
        "Critical": "var(--rd)",
    }[impact_band]

    with placeholder:
        hero(
            "Planning estimate",
            'Cyber <span class="ct-grad">impact simulator</span>',
            "Estimate the business impact of a hypothetical incident with a transparent, "
            "rule-based score. It is a planning aid, not a prediction of a real breach.",
            chips=[incident_type, f"Severity {severity_label}", f"Exposure {exposure_label}"],
            side_html=ring(impact_score, f"{impact_band} impact", band_color, suffix="", size=170),
        )

    section("Factor breakdown", "Contribution = factor score × weight")
    bars = ""
    for name, selected, points, weight in factors:
        contribution = points * weight
        bars += (
            f'<div class="ct-factor"><div>{esc(name)}<small>{esc(selected)} · weight {weight:.0%}</small></div>'
            f'<div class="ct-bar"><i style="width:{points}%"></i></div>'
            f'<em>+{contribution:.1f}</em></div>'
        )
    h(f'<div class="ct-card">{bars}</div>')

    section("Suggested response priorities")
    if impact_band in ("High", "Critical"):
        priorities = [
            "Validate the incident scope and affected assets with authorized telemetry.",
            "Contain confirmed compromised accounts or hosts according to the response playbook.",
            "Preserve logs and evidence; document actions and timestamps.",
            "Escalate to the incident response lead and relevant business owner.",
        ]
    elif impact_band == "Moderate":
        priorities = [
            "Verify the alert and identify affected accounts, systems, and data.",
            "Increase monitoring and preserve relevant logs.",
            "Follow the organization's escalation and containment procedures if confirmed.",
        ]
    else:
        priorities = [
            "Validate the alert context and confirm whether the activity is expected.",
            "Record findings and continue routine monitoring.",
        ]

    h("".join(
        f'<div class="ct-action"><i>{i}</i><span>{esc(p)}</span></div>'
        for i, p in enumerate(priorities, start=1)
    ))

    st.info(
        "Methodology: weighted average of five factors (severity 30%, asset criticality 25%, "
        "exposure 20%, data sensitivity 15%, recovery time 10%). Weights and point mappings are "
        "heuristic defaults for demonstration and are not calibrated against real incident-loss data."
    )
    st.caption(
        "Cyber Impact Simulator is a custom CyberTrace AI demonstration feature. "
        "Its score is explainable and illustrative, not a validated financial-loss estimate."
    )
    st.stop()


# =========================================================
# PAGE: DETECTION EVALUATION
# =========================================================

if page == "Detection Evaluation":

    evaluation = st.session_state.get("detection_evaluation")
    rule_evaluation = st.session_state.get("rule_evaluation")

    hero(
        "Detection quality",
        'How good are the <span class="ct-grad">detections?</span>',
        "Measure the deterministic SOC rules against known attack and benign scenarios: "
        "precision, recall, false positives, and rule-level coverage.",
        chips=["Precision", "Recall", "F1 score", "Rule coverage"],
    )

    if st.button("Run detection evaluation", type="primary"):
        with st.spinner("Evaluating detection rules..."):
            attack_cases = get_attack_cases()
            benign_cases = get_benign_cases()

            evaluation = evaluate_dataset(
                attack_cases=[case["events"] for case in attack_cases],
                benign_cases=[case["events"] for case in benign_cases],
            )
            rule_evaluation = run_rule_evaluation()

            st.session_state["detection_evaluation"] = evaluation
            st.session_state["rule_evaluation"] = rule_evaluation

    if evaluation is None:
        st.info("Select **Run detection evaluation** to test the detection engine.")
        st.stop()

    metrics = evaluation["metrics"]

    section("Detection metrics", "Higher is better, except false-positive rate")
    cols = st.columns(4, gap="medium")
    ring_specs = [
        ("Precision", metrics["precision"], "var(--cy)"),
        ("Recall", metrics["recall"], "var(--vi)"),
        ("F1 score", metrics["f1_score"], "var(--gr)"),
        ("False-positive rate", metrics["false_positive_rate"], "var(--am)"),
    ]
    for col, (label, value, color) in zip(cols, ring_specs):
        with col:
            h(
                '<div class="ct-card" style="display:flex;flex-direction:column;align-items:center;gap:8px">'
                + ring(value * 100, label, color, size=150)
                + "</div>"
            )

    section("Confusion matrix", "How every test case was classified")
    cm_col, cov_col = st.columns([1.5, 1], gap="large")
    with cm_col:
        h(
            '<div class="ct-cm">'
            f'<div class="cm-tp"><span>True positives</span><b>{esc(metrics["true_positive"])}</b></div>'
            f'<div class="cm-fp"><span>False positives</span><b>{esc(metrics["false_positive"])}</b></div>'
            f'<div class="cm-fn"><span>False negatives</span><b>{esc(metrics["false_negative"])}</b></div>'
            f'<div class="cm-tn"><span>True negatives</span><b>{esc(metrics["true_negative"])}</b></div>'
            "</div>"
        )
    with cov_col:
        coverage = metrics["detection_coverage"]
        h(
            '<div class="ct-card" style="display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px">'
            + ring(coverage * 100, "Attack coverage", "var(--pk)", size=170)
            + "</div>"
        )

    section("Rule-level coverage", "Expected vs detected rules per attack scenario")
    rule_rows = [
        {
            "Attack scenario": r["name"],
            "Expected rules": ", ".join(r["expected_rules"]),
            "Detected rules": ", ".join(r["actual_rules"]),
            "Missing rules": ", ".join(r["missing_rules"]) or "None",
            "Unexpected rules": ", ".join(r["unexpected_rules"]) or "None",
            "Coverage": f"{r['coverage']:.0%}",
        }
        for r in rule_evaluation["attack_results"]
    ]
    st.dataframe(rule_rows, use_container_width=True, hide_index=True)

    section("Benign activity testing", "Normal behavior should stay quiet")
    benign_rows = [
        {
            "Test case": r["name"],
            "Status": "Clean" if r["clean"] else "Alert triggered",
            "Triggered rules": ", ".join(r["actual_rules"]) if r["actual_rules"] else "None",
        }
        for r in rule_evaluation["benign_results"]
    ]
    st.dataframe(benign_rows, use_container_width=True, hide_index=True)

    section("Case-level results")
    case_rows = [
        {
            "Case ID": r["case_id"],
            "Classification": r["classification"],
            "Detected": r["detected"],
            "Finding count": r["finding_count"],
        }
        for r in evaluation["results"]
    ]
    st.dataframe(case_rows, use_container_width=True, hide_index=True)

    st.success("Detection evaluation completed.")
    st.stop()


# =========================================================
# PAGE: INCIDENT INVESTIGATION  (run pipeline)
# =========================================================

if run_investigation:
    try:
        if input_mode == "Attack Simulator":
            simulator_events = generate_attack(scenario)

            # Apply the analyst-provided context to the generated events
            for event in simulator_events:
                if username:
                    event["user"] = username
                if source_ip:
                    event["source_ip"] = source_ip

            st.session_state["simulator_events"] = simulator_events

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as handle:
                json.dump(simulator_events, handle, indent=2)
                event_path = handle.name
        else:
            st.session_state["simulator_events"] = None
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as handle:
                handle.write(uploaded_file.getvalue().decode("utf-8"))
                event_path = handle.name

        with st.spinner("Investigating incident..."):
            result = investigate_incident(event_path, use_llm=use_llm)

        st.session_state["investigation_result"] = result

    except Exception as exc:
        st.error(f"Investigation failed: {type(exc).__name__}: {exc}")
        st.stop()

result = st.session_state.get("investigation_result")
paint_radar(result)


# =========================================================
# LANDING (no investigation yet)
# =========================================================

if result is None:

    hero(
        "Ready for your first investigation",
        'See the signal.<br><span class="ct-grad">Understand the threat.</span>',
        "Run a safe simulated attack or upload event JSON. CyberTrace turns raw security "
        "activity into a clear timeline, evidence-backed detections, and response guidance.",
        chips=["MITRE ATT&CK mapping", "Threat intelligence", "Gemini analyst", "Incident report"],
        side_html=ring(100, "System ready", "var(--gr)", suffix="", size=170),
    )

    section("Start with a workflow", "Pick one from the left panel or below")
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        h(feature_card("🔎", "Investigate an incident",
                       "Upload event JSON or generate a synthetic scenario, then follow the evidence from event to finding."))
    with c2:
        h(feature_card("📊", "Evaluate detections",
                       "Measure precision, recall, rule coverage, and false positives against known cases."))
    with c3:
        h(feature_card("🧮", "Estimate cyber impact",
                       "Explore an explainable, illustrative impact score built on transparent assumptions."))

    section("How an investigation runs")
    h(
        '<div class="ct-pipe">'
        '<div class="ct-step"><i>1</i><b>Ingest</b><small>Load events from a file or the attack simulator.</small></div>'
        '<div class="ct-step"><i>2</i><b>Detect</b><small>Deterministic rules flag suspicious behavior.</small></div>'
        '<div class="ct-step"><i>3</i><b>Map</b><small>Findings are tied to MITRE ATT&CK techniques.</small></div>'
        '<div class="ct-step"><i>4</i><b>Assess</b><small>The analyst engine explains the threat.</small></div>'
        '<div class="ct-step"><i>5</i><b>Report</b><small>Download a ready-to-share incident report.</small></div>'
        "</div>"
    )
    st.caption("Simulator scenarios generate synthetic telemetry. Uploaded files follow the configured investigation pipeline.")
    st.stop()


# =========================================================
# INCIDENT COMMAND DASHBOARD
# =========================================================

summary = result["summary"]
findings = result.get("findings", [])
events = result.get("events", [])
timeline = result.get("timeline", [])
ai_assessment = result.get("ai_assessment", {})

incident_id = summary.get("incident_id", "-")
incident_severity = summary.get("severity", "-")
event_count = summary.get("event_count", 0)
finding_count = summary.get("finding_count", len(findings))
confidence_value = ai_assessment.get("confidence", 0) or 0

hero(
    "Live investigation",
    f'Incident <span class="ct-grad">{esc(incident_id)}</span>',
    ai_assessment.get(
        "threat_summary",
        "One workspace for the incident timeline, detection evidence, and response decisions.",
    ).split("\n")[0][:220],
    chips=[
        f"{event_count} events",
        f"{finding_count} detections",
        "Gemini analyst" if use_llm else "Offline analyst",
    ],
    side_html=(
        '<div style="display:flex;flex-direction:column;align-items:center;gap:12px">'
        + ring(confidence_value, "Analyst confidence", "var(--cy)", size=160)
        + sev_badge(incident_severity)
        + "</div>"
    ),
)

k1, k2, k3, k4 = st.columns(4, gap="medium")
with k1:
    h(kpi("Events analyzed", event_count, "Telemetry records ingested", "var(--cy)"))
with k2:
    h(kpi("Detections", finding_count, "Rules triggered", "var(--vi)"))
with k3:
    h(kpi("Severity", incident_severity, "Overall incident rating", sev_color(incident_severity)))
with k4:
    h(kpi("Analyst confidence", f"{confidence_value}%", "Assessment certainty", "var(--gr)"))

st.write("")

overview_tab, findings_tab, intel_tab, analyst_tab, report_tab, data_tab = st.tabs([
    "Overview",
    f"Detections ({len(findings)})",
    "Threat intelligence",
    "AI assessment",
    "Incident report",
    "Event data",
])

# ---------------------------------------------------------
# OVERVIEW
# ---------------------------------------------------------
with overview_tab:
    left, right = st.columns([1.7, 1], gap="large")

    with left:
        section("Incident timeline", "Chronological view of observed activity")
        if timeline:
            st.dataframe(timeline, use_container_width=True, hide_index=True)
        else:
            st.info("No timeline events are available.")

    with right:
        section("Severity mix", "Detections by severity")
        counts = {}
        for finding in findings:
            key = str(finding.get("severity", "Unknown"))
            counts[key] = counts.get(key, 0) + 1
        if counts:
            total = sum(counts.values())
            rows = "".join(
                f'<div class="ct-factor" style="grid-template-columns:90px 1fr 34px">'
                f'<div>{sev_badge(sev)}</div>'
                f'<div class="ct-bar"><i style="width:{n / total * 100:.0f}%;background:{sev_color(sev)}"></i></div>'
                f'<em>{n}</em></div>'
                for sev, n in sorted(counts.items(), key=lambda kv: -kv[1])
            )
            h(f'<div class="ct-card">{rows}</div>')
        else:
            st.success("No detection rules triggered.")

        section("MITRE ATT&CK tactics")
        tactics = []
        for finding in findings:
            tactic = (finding.get("mitre") or {}).get("tactic")
            if tactic and tactic not in tactics:
                tactics.append(tactic)
        if tactics:
            h('<div class="ct-chips">' + "".join(f'<span class="ct-chip">{esc(t)}</span>' for t in tactics) + "</div>")
        else:
            st.caption("No tactics mapped.")

# ---------------------------------------------------------
# DETECTIONS
# ---------------------------------------------------------
with findings_tab:
    section("Detection findings", "Rule-triggered evidence mapped to severity and MITRE ATT&CK")
    if not findings:
        st.success("No detection rules triggered for this investigation.")
    else:
        for finding in findings:
            rule_id = finding.get("rule_id", "-")
            title = finding.get("title", "Detection")
            severity = finding.get("severity", "Unknown")
            confidence = finding.get("confidence", 0) or 0
            mitre = finding.get("mitre", {}) or {}
            evidence = finding.get("evidence", "-")
            if not isinstance(evidence, str):
                evidence = json.dumps(evidence, indent=2, default=str)

            h(
                f'<div class="ct-find" style="--acc:{sev_color(severity)}">'
                f'<div class="ct-find-top"><div class="ct-find-title"><code>{esc(rule_id)}</code>{esc(title)}</div>'
                f'{sev_badge(severity)}</div>'
                f'<div class="ct-meta">'
                f'<span class="ct-tag">Tactic <b>{esc(mitre.get("tactic", "-"))}</b></span>'
                f'<span class="ct-tag">Technique <b>{esc(mitre.get("technique_id", "-"))}</b> {esc(mitre.get("technique_name", "-"))}</span>'
                f'</div>'
                f'<div class="ct-conf">Confidence<div class="ct-bar"><i style="width:{min(100, float(confidence)):.0f}%"></i></div>{esc(confidence)}%</div>'
                f'<div class="ct-evidence">{esc(evidence)}</div></div>'
            )

# ---------------------------------------------------------
# THREAT INTELLIGENCE
# ---------------------------------------------------------
with intel_tab:
    section("Threat intelligence", "Indicators are deduplicated by source IP; the highest-confidence record is shown")
    ti_by_ip = {}
    for event in events:
        ti = event.get("threat_intel")
        if not ti:
            continue
        indicator_ip = ti.get("source_ip", "-")
        if indicator_ip == "-":
            continue
        current = ti_by_ip.get(indicator_ip)
        if current is None or ti.get("confidence", 0) > current.get("confidence", 0):
            ti_by_ip[indicator_ip] = ti

    if ti_by_ip:
        ti_rows = [
            {
                "Source IP": ip,
                "Reputation": ti.get("reputation", "-"),
                "Confidence": f"{ti.get('confidence', 0)}%",
                "Type": ti.get("type", "-"),
                "Source": ti.get("source", "-"),
                "Description": ti.get("description", "-"),
            }
            for ip, ti in ti_by_ip.items()
        ]
        st.dataframe(ti_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No threat-intelligence indicators were available.")

# ---------------------------------------------------------
# AI ASSESSMENT
# ---------------------------------------------------------
with analyst_tab:
    attack_technique = ai_assessment.get("attack_technique", "-")
    assessment_severity = ai_assessment.get("severity", "-")
    threat_summary = ai_assessment.get("threat_summary", ai_assessment.get("explanation", "-"))
    recommended_actions = ai_assessment.get("recommended_actions", [])
    reasoning = ai_assessment.get("reasoning", [])

    section("AI analyst assessment", "Gemini analyst" if use_llm else "Deterministic analyst · no external API call")

    top_left, top_right = st.columns([2, 1], gap="large")
    with top_left:
        h(f'<div class="ct-summary">{esc(threat_summary)}</div>')
        h(
            f'<div class="ct-meta"><span class="ct-tag">Attack classification <b>{esc(attack_technique)}</b></span></div>'
        )
    with top_right:
        h(
            '<div class="ct-card" style="display:flex;flex-direction:column;align-items:center;gap:12px">'
            + ring(confidence_value, "Confidence", "var(--vi)", size=140)
            + sev_badge(assessment_severity)
            + "</div>"
        )

    action_col, reasoning_col = st.columns(2, gap="large")
    with action_col:
        section("Recommended actions")
        if recommended_actions:
            h("".join(
                f'<div class="ct-action"><i>{i}</i><span>{esc(a)}</span></div>'
                for i, a in enumerate(recommended_actions, start=1)
            ))
        else:
            st.info("No recommended actions were returned.")
    with reasoning_col:
        section("Evidence-linked reasoning")
        if reasoning:
            h("".join(f'<div class="ct-reason">{esc(item)}</div>' for item in reasoning))
        else:
            st.info("No reasoning items were returned.")

# ---------------------------------------------------------
# REPORT
# ---------------------------------------------------------
with report_tab:
    section("Analyst report", "Ready to share with your team")
    try:
        report_markdown = render_markdown_report(result)
        st.download_button(
            label="Download incident report",
            data=report_markdown,
            file_name="incident_report.md",
            mime="text/markdown",
            type="primary",
        )
        with st.expander("Preview report", expanded=True):
            st.markdown(report_markdown)
    except Exception as exc:
        st.warning(f"Unable to generate report preview: {type(exc).__name__}: {exc}")

# ---------------------------------------------------------
# EVENT DATA
# ---------------------------------------------------------
with data_tab:
    section("Investigation data", "Generated telemetry and the complete structured result")
    stored_simulator_events = st.session_state.get("simulator_events")
    if stored_simulator_events:
        with st.expander("Generated attack telemetry"):
            st.json(stored_simulator_events)
    with st.expander("Raw investigation output"):
        st.json(result)