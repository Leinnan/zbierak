(function () {
  "use strict";

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
  }

  function prepareStackTraces(root) {
    root.querySelectorAll(".stack-trace code:not([data-prepared])").forEach(function (code) {
      var lines = code.textContent.split("\n");
      var applicationFrames = 0;
      code.textContent = "";
      lines.forEach(function (line, index) {
        var row = document.createElement("span");
        row.className = "stack-line";
        if (/\b(src\/|app\/|crates\/|\.rs:\d+|\.js:\d+|\.ts:\d+)/.test(line) && !/\b(node_modules|\/rustc\/|site-packages|vendor)\b/.test(line)) {
          row.classList.add("is-app");
          applicationFrames += 1;
        }
        row.textContent = line + (index < lines.length - 1 ? "\n" : "");
        code.appendChild(row);
      });
      code.dataset.prepared = "true";
      if (applicationFrames > 0) code.closest(".stack-trace").dataset.mode = "app";
    });
  }

  function localizeTimes(root) {
    root.querySelectorAll("time.js-local-time:not([data-localized])").forEach(function (element) {
      var date = element.dataset.unix
        ? new Date(Number(element.dataset.unix) * 1000)
        : new Date(element.dateTime);
      if (Number.isNaN(date.getTime())) return;
      element.textContent = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
      element.dateTime = date.toISOString();
      element.title = date.toISOString();
      element.dataset.localized = "true";
    });
  }

  function formatJson(root) {
    root.querySelectorAll("code.js-json:not([data-formatted])").forEach(function (element) {
      try {
        element.textContent = JSON.stringify(JSON.parse(element.textContent), null, 2);
        element.dataset.formatted = "true";
      } catch (_) {
        // Preserve malformed or future non-JSON payloads exactly as received.
      }
    });
  }

  function syncThemeControls(root) {
    if (!window.ZbierakTheme) return;
    var preference = window.ZbierakTheme.get();
    root.querySelectorAll("[data-theme-select]").forEach(function (select) {
      select.value = preference;
    });
  }

  // Toolbar actions that stay available; icons are rendered from CSS glyph
  // classes so no Font Awesome download is attempted (the CSP allows
  // same-origin resources only).
  var EDITOR_TOOLBAR = [
    "bold", "italic", "strikethrough", "|",
    "heading", "code", "quote", "|",
    "unordered-list", "ordered-list", "|",
    "link", "|", "preview", "side-by-side", "fullscreen"
  ];
  var EDITOR_ICONS = {
    bold: "zb-icon-bold",
    italic: "zb-icon-italic",
    strikethrough: "zb-icon-strike",
    heading: "zb-icon-heading",
    code: "zb-icon-code",
    quote: "zb-icon-quote",
    "unordered-list": "zb-icon-ul",
    "ordered-list": "zb-icon-ol",
    link: "zb-icon-link",
    preview: "zb-icon-preview",
    "side-by-side": "zb-icon-side",
    fullscreen: "zb-icon-full"
  };

  // The editor's live preview runs in the browser, one step removed from the
  // server-side sanitizer, so strip the obvious vectors there as well.
  // DOMParser documents never execute scripts or fetch subresources.
  function stripPreviewHtml(html) {
    var doc = new DOMParser().parseFromString(html, "text/html");
    doc.querySelectorAll(
      "script, iframe, object, embed, style, link, meta, base, form, input, button, textarea, select, audio, video, source, track, frame, frameset, applet, svg, math"
    ).forEach(function (element) { element.remove(); });
    doc.querySelectorAll("*").forEach(function (element) {
      Array.prototype.slice.call(element.attributes).forEach(function (attribute) {
        var name = attribute.name.toLowerCase();
        var value = attribute.value.trim().toLowerCase().replace(/\s+/g, "");
        var urlBearer = name === "href" || name === "src" || name === "xlink:href";
        var dangerous = name.indexOf("on") === 0 || name === "style" || name === "id"
          || (urlBearer && (value.indexOf("javascript:") === 0 || value.indexOf("data:") === 0));
        if (dangerous) element.removeAttribute(attribute.name);
      });
    });
    return doc.body.innerHTML;
  }

  function setupMarkdownEditors(root) {
    if (!window.EasyMDE) return;
    root.querySelectorAll("textarea[data-markdown-editor]:not([data-prepared])").forEach(function (textarea) {
      textarea.dataset.prepared = "true";
      var iconMap = {};
      Object.keys(EDITOR_ICONS).forEach(function (name) {
        iconMap[name] = "zb-icon " + EDITOR_ICONS[name];
      });
      try {
        new window.EasyMDE({
          element: textarea,
          autoDownloadFontAwesome: false,
          spellChecker: false,
          uploadImage: false,
          minHeight: "160px",
          placeholder: textarea.getAttribute("placeholder") || "",
          status: ["lines", "words"],
          toolbar: EDITOR_TOOLBAR,
          iconClassMap: iconMap,
          renderingConfig: { sanitizerFunction: stripPreviewHtml }
        });
      } catch (_) {
        // If the editor cannot start, the plain textarea still works and
        // submits valid Markdown, so no fallback handling is needed.
      }
    });
  }

  function showCopyFeedback(button) {
    var original = button.textContent;
    button.textContent = "Copied";
    button.classList.add("copy-success");
    window.setTimeout(function () {
      button.textContent = original;
      button.classList.remove("copy-success");
    }, 1600);
  }

  function enhance(root) {
    prepareStackTraces(root);
    localizeTimes(root);
    formatJson(root);
    syncThemeControls(root);
    setupMarkdownEditors(root);
  }

  document.addEventListener("DOMContentLoaded", function () {
    enhance(document);

    var projectName = document.getElementById("project-name");
    var projectSlug = document.getElementById("project-slug");
    if (projectName && projectSlug) {
      var slugEdited = false;
      projectSlug.addEventListener("input", function () { slugEdited = projectSlug.value.length > 0; });
      projectName.addEventListener("input", function () {
        if (slugEdited) return;
        projectSlug.value = projectName.value.toLowerCase().trim()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-+|-+$/g, "")
          .slice(0, 50);
      });
    }

    document.addEventListener("click", function (event) {
      var sidebarButton = event.target.closest("[data-sidebar-toggle]");
      if (sidebarButton) {
        var sidebar = document.getElementById("app-sidebar");
        var open = sidebar && sidebar.classList.toggle("is-open");
        sidebarButton.setAttribute("aria-expanded", String(Boolean(open)));
        return;
      }

      if (event.target.closest("[data-history-back]")) {
        window.history.back();
        return;
      }

      var confirmTarget = event.target.closest("[data-confirm]");
      if (confirmTarget && !window.confirm(confirmTarget.dataset.confirm)) {
        event.preventDefault();
        return;
      }

      var modeButton = event.target.closest("[data-stack-mode]");
      if (modeButton) {
        var trace = document.querySelector(".stack-trace");
        if (!trace) return;
        trace.dataset.mode = modeButton.dataset.stackMode === "app" ? "app" : "all";
        document.querySelectorAll("[data-stack-mode]").forEach(function (button) {
          button.classList.toggle("is-active", button === modeButton);
        });
        return;
      }

      var copyUrlButton = event.target.closest("[data-copy-url]");
      if (copyUrlButton && navigator.clipboard) {
        var url = copyUrlButton.dataset.copyUrl;
        fetch(url, { credentials: "same-origin", headers: { Accept: "text/markdown" } })
          .then(function (response) {
            if (!response.ok) throw new Error("export failed");
            return response.text();
          })
          .then(function (text) { return navigator.clipboard.writeText(text); })
          .then(function () { showCopyFeedback(copyUrlButton); })
          .catch(function () { window.open(url, "_blank"); });
        return;
      }

      var copyButton = event.target.closest("[data-copy], [data-copy-target]");
      if (copyButton && navigator.clipboard) {
        var target = copyButton.dataset.copyTarget && document.querySelector(copyButton.dataset.copyTarget);
        var value = copyButton.dataset.copy || (target ? target.textContent : "");
        navigator.clipboard.writeText(value).then(function () {
          showCopyFeedback(copyButton);
        });
      }
    });

    document.addEventListener("change", function (event) {
      var select = event.target.closest("[data-theme-select]");
      if (select && window.ZbierakTheme) window.ZbierakTheme.set(select.value);
    });
  });

  document.addEventListener("zbierak:themechange", function () {
    syncThemeControls(document);
  });

  document.addEventListener("htmx:configRequest", function (event) {
    var token = csrfToken();
    if (token) event.detail.headers["X-CSRF-Token"] = token;
  });

  document.addEventListener("htmx:afterSwap", function (event) {
    enhance(event.detail.target);
  });

  document.addEventListener("htmx:responseError", function () {
    var region = document.getElementById("flash-region");
    if (region) region.innerHTML = '<div class="alert alert-danger" role="alert">The request failed. Your changes may not have been saved.</div>';
  });
})();
