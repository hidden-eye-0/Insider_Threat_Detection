"""macOS-style magnifying dock navbar (vanilla port of the React Bits <Dock />, as a Streamlit v2 component).

Ported: magnification by pointer distance, spring-eased sizing, hover labels, active dot, badges, separators,
click hop, keyboard focus, light theme. Not ported: right-click menus, autoHide, multi-edge positions.
"""
import streamlit as st
import streamlit.components.v2 as components

_CSS = """
.dock-wrap { position: fixed; left: 50%; bottom: 14px; transform: translateX(-50%); z-index: 999990; pointer-events: none; }
.dock { display: flex; align-items: flex-end; gap: 10px; padding: 9px 12px; height: 68px; box-sizing: border-box;
  border-radius: 24px; pointer-events: auto; background: rgba(240,240,243,.82);
  box-shadow: inset 0 0 0 1px rgba(24,24,27,.07), inset 0 1px 0 rgba(255,255,255,.95), 0 22px 44px -22px rgba(24,24,27,.3), 0 6px 16px -10px rgba(24,24,27,.16);
  -webkit-backdrop-filter: blur(20px) saturate(1.6); backdrop-filter: blur(20px) saturate(1.6); }
.item { position: relative; flex: none; width: 50px; height: 50px; border: 0; padding: 0; margin: 0; background: none; cursor: pointer; outline: none; color: #27272a; }
.face { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; border-radius: 16px;
  background: linear-gradient(180deg,#fff 0%,#f6f6f8 100%);
  box-shadow: inset 0 0 0 1px rgba(24,24,27,.08), inset 0 1px 0 #fff, 0 4px 10px -5px rgba(24,24,27,.25); transition: filter .2s; }
.item:active .face { filter: brightness(.9); transition-duration: 0s; }
.item:focus-visible .face { outline: 2px solid #0a84ff; outline-offset: 3px; }
.item.active .face { background: linear-gradient(180deg,#eef0ff 0%,#e1e5ff 100%); color: #4f46e5; }
.ico { font-family: 'Material Symbols Rounded','Material Symbols Outlined'; font-weight: normal; font-style: normal; line-height: 1;
  letter-spacing: normal; text-transform: none; white-space: nowrap; font-feature-settings: 'liga'; -webkit-font-feature-settings: 'liga';
  font-size: 24px; user-select: none; }
.dot { position: absolute; left: 50%; margin-left: -2px; top: calc(100% + 3px); width: 4px; height: 4px; border-radius: 50%; background: rgba(24,24,27,.55); }
.badge { position: absolute; top: -7px; right: -7px; min-width: 19px; height: 19px; padding: 0 5px; box-sizing: border-box; border-radius: 10px;
  background: #ff453a; color: #fff; font: 600 11px/19px system-ui,sans-serif; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.3); }
.label { position: absolute; bottom: calc(100% + 12px); left: 50%; transform: translate(-50%,4px); padding: 6px 10px; border-radius: 8px; background: #fff;
  color: #18181b; font: 500 12px/1 system-ui,sans-serif; white-space: nowrap; pointer-events: none; opacity: 0; transition: opacity .16s, transform .16s;
  box-shadow: inset 0 0 0 1px rgba(24,24,27,.07), 0 8px 20px -8px rgba(0,0,0,.35); }
.item:hover .label, .item:focus-visible .label { opacity: 1; transform: translate(-50%,0); }
.sep { flex: none; align-self: center; width: 1px; height: 36px; border-radius: 1px; background: rgba(24,24,27,.12); }
@media (max-width: 640px) { .dock { gap: 5px; padding: 8px; } .item { width: 38px; height: 38px; } }
"""

_JS = """
export default function ({ parentElement, data, setTriggerValue }) {
  const root = parentElement;
  const BASE = 50, PEAK = 70, DIST = 200, K = 150 / 0.1, C = 12 / 0.1;
  const items = data.items || [];
  let wrap = root.querySelector('.dock-wrap');
  if (wrap) wrap.remove();
  wrap = document.createElement('div'); wrap.className = 'dock-wrap';
  const dock = document.createElement('div'); dock.className = 'dock'; dock.setAttribute('role', 'toolbar');
  wrap.appendChild(dock); root.appendChild(wrap);
  const st = [];
  items.forEach((it, i) => {
    if (it.separator) { const s = document.createElement('span'); s.className = 'sep'; dock.appendChild(s); st.push(null); return; }
    const b = document.createElement('button'); b.type = 'button'; b.className = 'item' + (it.active ? ' active' : ''); b.setAttribute('aria-label', it.label);
    const face = document.createElement('span'); face.className = 'face';
    const ico = document.createElement('span'); ico.className = 'ico'; ico.textContent = it.icon; face.appendChild(ico); b.appendChild(face);
    if (it.badge) { const g = document.createElement('span'); g.className = 'badge'; g.textContent = it.badge; b.appendChild(g); }
    if (it.active) { const d = document.createElement('span'); d.className = 'dot'; b.appendChild(d); }
    const l = document.createElement('span'); l.className = 'label'; l.textContent = it.label; b.appendChild(l);
    b.addEventListener('click', () => {
      b.animate([{ transform: 'translateY(0)' }, { transform: 'translateY(-14px)' }, { transform: 'translateY(0)' }], { duration: 380, easing: 'ease-out' });
      setTimeout(() => setTriggerValue('go', it.key), 180);
    });
    dock.appendChild(b); st.push({ el: b, face, size: BASE, v: 0 });
  });
  let px = null, raf = 0, last = 0;
  const reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  function tick(now) {
    raf = 0; const dt = Math.min(1 / 30, Math.max(.001, (now - last) / 1000)); last = now; let moving = false;
    st.forEach(s => {
      if (!s) return;
      const r = s.el.getBoundingClientRect(); const c = r.left + r.width / 2;
      const reach = px === null ? 1 : Math.abs(px - c) / DIST;
      const target = BASE + (PEAK - BASE) * (reach < 1 ? Math.cos(reach * Math.PI / 2) ** 2 : 0);
      if (reduce) { s.size = target; s.v = 0; } else {
        const n = Math.max(1, Math.ceil(dt * 240)), h = dt / n;
        for (let i = 0; i < n; i++) { s.v = (s.v + h * K * (target - s.size)) / (1 + h * C + h * h * K); s.size += s.v * h; }
      }
      if (Math.abs(s.v) < .01 && Math.abs(target - s.size) < .01) { s.size = target; s.v = 0; } else moving = true;
      s.el.style.width = s.size + 'px'; s.el.style.height = s.size + 'px';
    });
    if (moving) raf = requestAnimationFrame(tick);
  }
  const wake = () => { if (!raf) { last = performance.now(); raf = requestAnimationFrame(tick); } };
  dock.addEventListener('pointermove', e => { px = e.clientX; wake(); });
  dock.addEventListener('pointerleave', () => { px = null; wake(); });
}
"""

_dock = components.component("sentinel_dock", css=_CSS, js=_JS, isolate_styles=True)


def dock(items: list[dict], key: str = "nav_dock") -> str | None:
    """Render the dock; return the `key` of an item clicked on this run (else None)."""
    res = _dock(data={"items": items}, key=key, on_go_change=lambda: None)
    return res.go if getattr(res, "go", None) else None
