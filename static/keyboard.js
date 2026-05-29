(() => {
  const $ = (id) => document.getElementById(id);
  const drawer = $("detail-drawer"), backdrop = $("drawer-backdrop");
  const palette = $("command-palette"), paletteInput = $("palette-input");
  const toasts = $("toast-container");
  const rows = () => Array.from(document.querySelectorAll("tr.selectable-row:not([hidden])"));
  const isTyping = (el) => Boolean(el && (["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || el.isContentEditable));

  const selectRow = (idx) => {
    const list = rows();
    if (!list.length) return;
    const clamped = Math.max(0, Math.min(idx, list.length - 1));
    list.forEach((r) => r.classList.remove("is-selected"));
    list[clamped].classList.add("is-selected");
    list[clamped].scrollIntoView({ block: "nearest" });
  };

  const openDrawer = (row) => {
    if (!drawer || !row) return;
    $("drawer-title").textContent = row.dataset.title || "Details";
    const url = row.dataset.drawerUrl;
    if (url && window.htmx) window.htmx.ajax("GET", url, { target: "#drawer-body", swap: "innerHTML" });
    else {
      const tpl = $(row.dataset.detail || "");
      $("drawer-body").innerHTML = "";
      if (tpl?.content) $("drawer-body").appendChild(tpl.content.cloneNode(true));
    }
    drawer.classList.add("open");
    backdrop?.classList.add("open");
  };

  const closeDrawer = () => { drawer?.classList.remove("open"); backdrop?.classList.remove("open"); };
  const togglePalette = () => {
    if (!palette) return;
    if (palette.open) return palette.close();
    palette.showModal();
    if (paletteInput) { paletteInput.value = ""; paletteInput.focus(); }
  };

  document.addEventListener("click", (e) => {
    const row = e.target.closest?.("tr.selectable-row");
    if (!row || e.target.closest("a, button, input, select, form")) return;
    const idx = rows().indexOf(row);
    if (idx >= 0) selectRow(idx);
    openDrawer(row);
  });

  $("drawer-close")?.addEventListener("click", closeDrawer);
  backdrop?.addEventListener("click", closeDrawer);
  $("palette-open")?.addEventListener("click", togglePalette);

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault(); closeDrawer(); togglePalette(); return;
    }
    if (e.key === "Escape") { palette?.open ? palette.close() : closeDrawer(); return; }
    if (palette?.open || isTyping(document.activeElement)) return;
    const list = rows(), cur = list.findIndex((r) => r.classList.contains("is-selected"));
    if (e.key === "j" || e.key === "ArrowDown") { e.preventDefault(); selectRow(cur < 0 ? 0 : cur + 1); }
    else if (e.key === "k" || e.key === "ArrowUp") { e.preventDefault(); selectRow(cur < 0 ? 0 : cur - 1); }
    else if (e.key === "Enter" && cur >= 0) { e.preventDefault(); openDrawer(list[cur]); }
    else if (e.key === "c" || e.key === "n") {
      const btn = document.querySelector(`[data-shortcut='${e.key}']`) || document.querySelector("[data-shortcut='c']");
      if (btn) { e.preventDefault(); btn.click(); }
    } else if (["r", "s", "a", "e"].includes(e.key) && cur >= 0) {
      const btn = list[cur].querySelector(`[data-shortcut='${e.key}']`);
      if (btn) { e.preventDefault(); btn.click(); }
    }
  });

  document.body.addEventListener("htmx:afterSwap", (e) => {
    if (e.detail?.target?.id === "drawer-body") { drawer?.classList.add("open"); backdrop?.classList.add("open"); }
    if (rows().length && !document.querySelector("tr.selectable-row.is-selected")) selectRow(0);
  });

  document.body.addEventListener("showToast", (e) => {
    if (!toasts || !e.detail?.message) return;
    const el = document.createElement("div");
    el.className = `toast toast-${e.detail.level || "info"}`;
    el.setAttribute("role", "status");
    el.textContent = e.detail.message;
    toasts.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  });

  const themeBtn = $("theme-toggle");
  const isDark = () => (document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches);
  const applyTheme = (t) => {
    if (t) document.documentElement.dataset.theme = t;
    if (themeBtn) themeBtn.textContent = isDark() ? "Hell" : "Dunkel";
  };
  applyTheme(localStorage.getItem("ins-isms-theme") || "");
  themeBtn?.addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    localStorage.setItem("ins-isms-theme", next);
    applyTheme(next);
  });
  if (rows().length) selectRow(0);
})();
