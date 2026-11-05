"""Sentinel Intelligence design system: tokens, CSS, and reusable UI components (light theme).

All colours / spacing / typography are centralised here (and mirrored in .streamlit/config.toml)
so every page stays visually consistent.
"""
from __future__ import annotations

import html

import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

# ----------------------------------------------------------------------------- tokens
BG, CARD, BORDER = "#F5F7FB", "#FFFFFF", "#E7EAF1"
PRIMARY, SECONDARY = "#4F46E5", "#6366F1"
HEADING, BODY, MUTED = "#172033", "#64748B", "#94A3B8"
NAVY = "#1E1B4B"
SEVERITY = {"Critical": "#DC2626", "High": "#EA580C", "Medium": "#D97706", "Low": "#16A34A"}
SEVERITY_BG = {"Critical": "#FEE2E2", "High": "#FFEDD5", "Medium": "#FEF3C7", "Low": "#DCFCE7"}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
TONES = {  # soft accent containers: (background, foreground)
    "indigo": ("#EEF0FF", "#4F46E5"), "sky": ("#E0F2FE", "#0284C7"), "mint": ("#DCFCE7", "#059669"),
    "rose": ("#FFE4E6", "#E11D48"), "amber": ("#FEF3C7", "#D97706"), "lavender": ("#F3E8FF", "#7C3AED"),
    "slate": ("#F1F5F9", "#475569"),
}
STATUS_TONE = {"Pending review": "amber", "Under investigation": "sky", "Explained / legitimate": "mint",
               "Escalated": "rose", "Closed": "slate"}
CHART_COLORS = ["#4F46E5", "#0EA5E9", "#10B981", "#F59E0B", "#F43F5E", "#8B5CF6", "#64748B", "#14B8A6"]
FONT = "Inter, 'Segoe UI', system-ui, -apple-system, Roboto, 'Helvetica Neue', Arial, sans-serif"

CSS = f"""
<style>
:root {{
  --bg:{BG}; --card:{CARD}; --border:{BORDER}; --primary:{PRIMARY}; --secondary:{SECONDARY};
  --heading:{HEADING}; --body:{BODY}; --muted:{MUTED}; --navy:{NAVY};
  --radius:14px; --shadow:0 1px 2px rgba(23,32,51,.04), 0 4px 14px rgba(23,32,51,.04);
  --shadow-hover:0 2px 4px rgba(23,32,51,.06), 0 10px 24px rgba(79,70,229,.10);
  --t:180ms cubic-bezier(.4,0,.2,1);
}}
html, body, [class*="css"], .stApp {{ font-family:{FONT}; color:var(--body); }}
.stApp {{ background:var(--bg); }}
header[data-testid="stHeader"] {{ background:transparent; height:2.2rem; pointer-events:none; }}
header[data-testid="stHeader"] button, header[data-testid="stHeader"] a {{ pointer-events:auto; }}
[data-testid="stToolbar"], [data-testid="stDecoration"], footer {{ visibility:hidden; height:0; }}
.block-container {{ padding:2.6rem 2rem 4rem 2rem; max-width:1480px; }}
h1,h2,h3,h4,h5 {{ color:var(--heading); font-family:{FONT}; letter-spacing:-.015em; font-weight:650; }}
h3 {{ font-size:1.05rem; margin-bottom:.2rem; }}
p, li, label, .stMarkdown {{ color:var(--body); }}
a {{ color:var(--primary); }}
::selection {{ background:#C7D2FE; }}

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] {{ background:#fff; border-right:1px solid var(--border); }}
[data-testid="stSidebar"] > div:first-child {{ padding-top:.4rem; }}
[data-testid="stSidebarNav"] {{ padding-top:.2rem; }}
[data-testid="stSidebarNavSeparator"] {{ display:none; }}
[data-testid="stSidebarNav"] span[data-testid="stSidebarNavLinkContainer"] {{ gap:0; }}
[data-testid="stSidebarNavLink"] {{ border-radius:10px; margin:2px 8px; padding:.5rem .7rem; color:var(--body);
  transition:background var(--t), color var(--t); }}
[data-testid="stSidebarNavLink"]:hover {{ background:#F4F5FF; color:var(--primary); }}
[data-testid="stSidebarNavLink"][aria-current="page"] {{ background:#EEF0FF; color:var(--primary); font-weight:600;
  box-shadow: inset 3px 0 0 var(--navy); }}
[data-testid="stSidebarNavLink"] span {{ font-size:.92rem; }}
[data-testid="stNavSectionHeader"], [data-testid="stSidebarNav"] header {{ color:var(--muted) !important; font-size:.68rem;
  letter-spacing:.09em; text-transform:uppercase; padding-left:1rem; }}
.brand {{ display:flex; align-items:center; gap:.7rem; padding:.9rem .9rem .5rem .9rem; }}
.brand-logo {{ width:38px; height:38px; border-radius:11px; background:linear-gradient(135deg,#4F46E5,#6366F1);
  display:flex; align-items:center; justify-content:center; color:#fff; box-shadow:0 4px 12px rgba(79,70,229,.35); }}
.brand-logo .ms {{ font-size:22px; }}
.brand-name {{ color:var(--heading); font-weight:700; font-size:1.02rem; line-height:1.1; letter-spacing:-.01em; }}
.brand-sub {{ color:var(--muted); font-size:.74rem; margin-top:2px; }}
.side-note {{ margin:1rem .9rem; padding:.7rem .8rem; border-radius:12px; background:#F8FAFF; border:1px solid var(--border);
  font-size:.74rem; line-height:1.45; color:var(--body); }}

[data-testid="stSidebarHeader"] {{ padding:1rem 1rem .4rem 1rem; height:auto; }}
[data-testid="stSidebarHeader"] img, [data-testid="stLogo"] {{ height:2.9rem !important; max-width:100% !important; width:auto; }}
/* ---------- icons ---------- */
.ms {{ font-family:'Material Symbols Rounded','Material Symbols Outlined'; font-weight:normal; font-style:normal; font-size:20px;
  line-height:1; letter-spacing:normal; text-transform:none; display:inline-block; white-space:nowrap; direction:ltr;
  -webkit-font-feature-settings:'liga'; font-feature-settings:'liga'; vertical-align:middle; }}

/* ---------- cards ---------- */
[data-testid="stVerticalBlockBorderWrapper"] {{ background:var(--card); border:1px solid var(--border) !important;
  border-radius:var(--radius) !important; box-shadow:var(--shadow); transition:box-shadow var(--t), border-color var(--t); }}
[data-testid="stVerticalBlockBorderWrapper"]:hover {{ box-shadow:var(--shadow-hover); }}
[data-testid="stVerticalBlockBorderWrapper"] [data-testid="stVerticalBlockBorderWrapper"] {{ box-shadow:none; }}
.card-title {{ color:var(--heading); font-weight:650; font-size:.98rem; margin:0; }}
.card-sub {{ color:var(--muted); font-size:.78rem; margin:.1rem 0 .4rem 0; }}

.kpi {{ background:var(--card); border:1px solid var(--border); border-radius:var(--radius); padding:1rem 1.1rem;
  box-shadow:var(--shadow); transition:transform var(--t), box-shadow var(--t); height:100%; min-height:152px; }}
.kpi:hover {{ transform:translateY(-2px); box-shadow:var(--shadow-hover); }}
.kpi-top {{ display:flex; align-items:center; justify-content:space-between; }}
.kpi-label {{ color:var(--body); font-size:.8rem; font-weight:550; }}
.kpi-icon {{ width:36px; height:36px; border-radius:10px; display:flex; align-items:center; justify-content:center; }}
.kpi-value {{ color:var(--heading); font-size:1.85rem; font-weight:700; letter-spacing:-.025em; margin:.45rem 0 .1rem 0; line-height:1.1; }}
.kpi-sub {{ color:var(--muted); font-size:.76rem; display:flex; gap:.4rem; align-items:center; flex-wrap:wrap; }}
.trend-up {{ color:#DC2626; background:#FEE2E2; }} .trend-down {{ color:#059669; background:#DCFCE7; }} .trend-flat {{ color:#475569; background:#F1F5F9; }}
.trend {{ padding:1px 7px; border-radius:20px; font-weight:600; font-size:.72rem; }}

.badge {{ display:inline-flex; align-items:center; gap:.3rem; padding:2px 10px; border-radius:20px; font-size:.74rem; font-weight:600; line-height:1.5; white-space:nowrap; }}
.badge .dot {{ width:6px; height:6px; border-radius:50%; background:currentColor; }}

.page-head {{ margin:.2rem 0 1.1rem 0; }}
.crumbs {{ color:var(--muted); font-size:.78rem; margin-bottom:.25rem; }}
.crumbs b {{ color:var(--body); font-weight:600; }}
.page-title {{ color:var(--heading); font-size:1.65rem; font-weight:700; letter-spacing:-.025em; margin:0; line-height:1.2; }}
.page-sub {{ color:var(--body); font-size:.92rem; margin-top:.25rem; max-width:860px; }}

.empty {{ text-align:center; padding:2.2rem 1rem; border:1.5px dashed #D5DAE6; border-radius:var(--radius); background:#FAFBFE; }}
.empty .ms {{ font-size:34px; color:#A5B4FC; }} .empty h4 {{ margin:.4rem 0 .2rem 0; }} .empty p {{ margin:0; font-size:.86rem; }}

.callout {{ background:#F8FAFF; border:1px solid #DDE3F5; border-left:4px solid var(--primary); border-radius:10px;
  padding:.65rem .9rem; font-size:.84rem; color:#334155; }}
.callout.warn {{ background:#FFFBEB; border-color:#FDE68A; border-left-color:#D97706; }}

/* ---------- timeline ---------- */
.tl {{ position:relative; margin:.4rem 0 .2rem 0; padding-left:1.7rem; }}
.tl:before {{ content:''; position:absolute; left:.55rem; top:.3rem; bottom:.3rem; width:2px; background:#E2E6F0; }}
.tl-item {{ position:relative; padding:.45rem .75rem; margin-bottom:.4rem; border:1px solid var(--border); border-radius:10px;
  background:#fff; transition:border-color var(--t), box-shadow var(--t); }}
.tl-item:hover {{ border-color:#C7D2FE; box-shadow:var(--shadow-hover); }}
.tl-item.ctx {{ background:#FAFBFE; opacity:.82; }}
.tl-dot {{ position:absolute; left:-1.42rem; top:.85rem; width:12px; height:12px; border-radius:50%; border:3px solid #fff; box-shadow:0 0 0 1px #CBD5E1; }}
.tl-time {{ color:var(--muted); font-size:.72rem; font-variant-numeric:tabular-nums; }}
.tl-title {{ color:var(--heading); font-weight:600; font-size:.86rem; }}
.tl-meta {{ color:var(--body); font-size:.78rem; }}

.stepper {{ display:flex; gap:.4rem; flex-wrap:wrap; margin:.2rem 0 .6rem 0; }}
.step {{ flex:1 1 130px; padding:.5rem .7rem; border-radius:10px; border:1px solid var(--border); background:#fff; font-size:.78rem; text-align:center; color:var(--muted); }}
.step.done {{ background:#F0FDF4; color:#15803D; border-color:#BBF7D0; }}
.step.now {{ background:#EEF0FF; color:var(--primary); border-color:#C7D2FE; font-weight:700; }}

/* ---------- inputs & buttons ---------- */
.stTextInput input, .stNumberInput input, .stTextArea textarea, .stDateInput input,
div[data-baseweb="select"] > div {{ background:#fff !important; border:1px solid var(--border) !important; border-radius:10px !important;
  color:var(--heading) !important; transition:border-color var(--t), box-shadow var(--t); }}
.stTextInput input:focus, .stTextArea textarea:focus, div[data-baseweb="select"] > div:focus-within {{
  border-color:var(--secondary) !important; box-shadow:0 0 0 3px rgba(99,102,241,.18) !important; }}
.stTextInput label, .stSelectbox label, .stMultiSelect label, .stTextArea label, .stDateInput label, .stNumberInput label,
.stRadio label, .stCheckbox label {{ font-size:.8rem !important; font-weight:550; color:var(--body) !important; }}
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button, [data-testid="stPageLink"] a {{
  border-radius:10px; border:1px solid var(--border); background:#fff; color:var(--heading); font-weight:600; font-size:.86rem;
  transition:background var(--t), border-color var(--t), box-shadow var(--t), transform 90ms; }}
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {{
  border-color:#C7D2FE; background:#F4F5FF; color:var(--primary); box-shadow:0 2px 8px rgba(79,70,229,.12); }}
.stButton > button:active, .stDownloadButton > button:active {{ transform:scale(.98); }}
.stButton > button:focus-visible, .stDownloadButton > button:focus-visible, input:focus-visible, a:focus-visible {{
  outline:2px solid var(--secondary) !important; outline-offset:2px; }}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"], .stFormSubmitButton > button, .stDownloadButton > button[kind="primary"] {{
  background:var(--primary); border-color:var(--primary); color:#fff; }}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button:hover {{ background:#4338CA; color:#fff; border-color:#4338CA; }}
.stDownloadButton > button {{ background:#fff; }}
button[kind="primary"] p, .stFormSubmitButton > button p {{ color:#fff !important; }}

.stTabs [data-baseweb="tab-list"] {{ gap:.25rem; border-bottom:1px solid var(--border); }}
.stTabs [data-baseweb="tab"] {{ border-radius:8px 8px 0 0; color:var(--body); font-weight:600; font-size:.88rem; padding:.45rem .9rem; transition:color var(--t), background var(--t); }}
.stTabs [data-baseweb="tab"]:hover {{ color:var(--primary); background:#F4F5FF; }}
.stTabs [aria-selected="true"] {{ color:var(--primary) !important; }}
.stTabs [data-baseweb="tab-highlight"] {{ background:var(--primary); height:3px; }}
[data-testid="stDataFrame"] {{ border:1px solid var(--border); border-radius:12px; overflow:hidden; }}
[data-testid="stExpander"] {{ border:1px solid var(--border); border-radius:12px; background:#fff; }}
[data-testid="stMetric"] {{ background:#fff; border:1px solid var(--border); border-radius:12px; padding:.7rem .9rem; }}
[data-testid="stMetricLabel"] p {{ color:var(--body); font-size:.78rem; }} [data-testid="stMetricValue"] {{ color:var(--heading); font-weight:700; }}
[data-testid="stAlert"] {{ border-radius:12px; }}
div[role="dialog"] {{ border-radius:16px; }}

/* ---------- responsive ---------- */
@media (max-width: 900px) {{
  .block-container {{ padding:1rem .9rem 3rem .9rem; }}
  .page-title {{ font-size:1.35rem; }} .kpi-value {{ font-size:1.5rem; }} .kpi {{ min-height:0; }}
  [data-testid="stHorizontalBlock"] {{ flex-wrap:wrap; gap:.6rem; }}
  [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {{ min-width:calc(50% - .6rem) !important; flex:1 1 calc(50% - .6rem) !important; }}
}}
@media (max-width: 560px) {{
  [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {{ min-width:100% !important; flex:1 1 100% !important; }}
}}
@media (prefers-reduced-motion: reduce) {{ * {{ transition:none !important; animation:none !important; }} }}
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


# ----------------------------------------------------------------------------- components
def icon(name: str, size: int | None = None, color: str | None = None) -> str:
    style = "".join([f"font-size:{size}px;" if size else "", f"color:{color};" if color else ""])
    return f"<span class='ms' style='{style}' aria-hidden='true'>{name}</span>"


def badge(text: str, tone: str | None = None, dot: bool = True) -> str:
    if text in SEVERITY:
        bg, fg = SEVERITY_BG[text], SEVERITY[text]
    else:
        bg, fg = TONES.get(tone or STATUS_TONE.get(text, "slate"), TONES["slate"])
    d = "<span class='dot'></span>" if dot else ""
    return f"<span class='badge' style='background:{bg};color:{fg}'>{d}{html.escape(str(text))}</span>"


def page_header(title: str, subtitle: str, section: str) -> None:
    st.markdown(
        f"<div class='page-head'><div class='crumbs'>Sentinel Intelligence &nbsp;/&nbsp; {html.escape(section)} &nbsp;/&nbsp; "
        f"<b>{html.escape(title)}</b></div><div class='page-title'>{html.escape(title)}</div>"
        f"<div class='page-sub'>{html.escape(subtitle)}</div></div>", unsafe_allow_html=True)


def card_title(title: str, sub: str = "") -> None:
    st.markdown(f"<p class='card-title'>{html.escape(title)}</p>" + (f"<p class='card-sub'>{html.escape(sub)}</p>" if sub else ""),
                unsafe_allow_html=True)


def kpi(label: str, value: str, icon_name: str, tone: str = "indigo", sub: str = "", trend: tuple[float, str] | None = None,
        help_text: str = "") -> str:
    bg, fg = TONES[tone]
    t = ""
    if trend is not None:
        pct, label_t = trend
        cls = "trend-up" if pct > 0.5 else "trend-down" if pct < -0.5 else "trend-flat"
        arrow = "arrow_upward" if pct > 0.5 else "arrow_downward" if pct < -0.5 else "remove"
        t = f"<span class='trend {cls}'>{icon(arrow, 13)} {abs(pct):.0f}%</span><span>{html.escape(label_t)}</span>"
    title = f" title='{html.escape(help_text)}'" if help_text else ""
    return (f"<div class='kpi'{title}><div class='kpi-top'><span class='kpi-label'>{html.escape(label)}</span>"
            f"<span class='kpi-icon' style='background:{bg};color:{fg}'>{icon(icon_name, 20)}</span></div>"
            f"<div class='kpi-value'>{html.escape(value)}</div><div class='kpi-sub'>{t}<span>{html.escape(sub)}</span></div></div>")


def empty_state(title: str, text: str, icon_name: str = "inbox") -> None:
    st.markdown(f"<div class='empty'>{icon(icon_name)}<h4>{html.escape(title)}</h4><p>{html.escape(text)}</p></div>", unsafe_allow_html=True)


def callout(text: str, warn: bool = False) -> None:
    st.markdown(f"<div class='callout{' warn' if warn else ''}'>{text}</div>", unsafe_allow_html=True)


def stepper(statuses: list[str], current: str) -> None:
    idx = statuses.index(current) if current in statuses else 0
    parts = []
    for i, s in enumerate(statuses):
        cls = "now" if i == idx else "done" if i < idx else ""
        parts.append(f"<div class='step {cls}'>{html.escape(s)}</div>")
    st.markdown("<div class='stepper'>" + "".join(parts) + "</div>", unsafe_allow_html=True)


# ----------------------------------------------------------------------------- charts
_TEMPLATE = go.layout.Template(layout=dict(
    font=dict(family=FONT, size=12, color=BODY), colorway=CHART_COLORS, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    title=dict(font=dict(size=13, color=HEADING)), margin=dict(l=8, r=8, t=24, b=8),
    xaxis=dict(gridcolor="#EEF1F6", linecolor=BORDER, zeroline=False, tickfont=dict(color=BODY), title=dict(font=dict(color=BODY, size=11))),
    yaxis=dict(gridcolor="#EEF1F6", linecolor=BORDER, zeroline=False, tickfont=dict(color=BODY), title=dict(font=dict(color=BODY, size=11))),
    legend=dict(orientation="h", y=-0.22, x=0, font=dict(size=11), bgcolor="rgba(0,0,0,0)"),
    hoverlabel=dict(bgcolor="#fff", bordercolor=BORDER, font=dict(family=FONT, size=12, color=HEADING)),
    transition=dict(duration=350, easing="cubic-in-out")))
pio.templates["sentinel"] = _TEMPLATE


def style_fig(fig: go.Figure, height: int = 300) -> go.Figure:
    fig.update_layout(template="sentinel", height=height)
    return fig


def plot(fig: go.Figure, key: str | None = None, height: int = 300) -> None:
    st.plotly_chart(style_fig(fig, height), width="stretch", key=key, config={"displaylogo": False, "displayModeBar": False})


def severity_styler(df: pd.DataFrame, col: str = "priority"):
    """pandas Styler colouring severity cells consistently with the badges."""
    def f(v):
        if v in SEVERITY:
            return f"background-color:{SEVERITY_BG[v]};color:{SEVERITY[v]};font-weight:600"
        return ""
    return df.style.map(f, subset=[col])


def paginate(df: pd.DataFrame, key: str, sizes=(10, 25, 50, 100)) -> pd.DataFrame:
    """Return the current page of ``df`` with a compact pager. Selection indexes refer to the page slice."""
    n = len(df)
    c1, c2, c3 = st.columns([1, 1, 4])
    size = c1.selectbox("Rows per page", sizes, key=f"{key}_size", label_visibility="collapsed")
    pages = max(1, -(-n // size))
    page = c2.number_input("Page", 1, pages, 1, key=f"{key}_page", label_visibility="collapsed") if pages > 1 else 1
    start = (int(page) - 1) * size
    c3.markdown(f"<div style='padding-top:.45rem;font-size:.8rem;color:{MUTED}'>Showing {min(start + 1, n)}–{min(start + size, n)} of {n:,} "
                f"&middot; page {int(page)}/{pages}</div>", unsafe_allow_html=True)
    return df.iloc[start:start + size]
