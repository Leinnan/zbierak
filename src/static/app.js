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

  function enhance(root) {
    prepareStackTraces(root);
    localizeTimes(root);
    formatJson(root);
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

      var copyButton = event.target.closest("[data-copy], [data-copy-target]");
      if (copyButton && navigator.clipboard) {
        var target = copyButton.dataset.copyTarget && document.querySelector(copyButton.dataset.copyTarget);
        var value = copyButton.dataset.copy || (target ? target.textContent : "");
        navigator.clipboard.writeText(value).then(function () {
          var original = copyButton.textContent;
          copyButton.textContent = "Copied";
          copyButton.classList.add("copy-success");
          window.setTimeout(function () {
            copyButton.textContent = original;
            copyButton.classList.remove("copy-success");
          }, 1600);
        });
      }
    });
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
