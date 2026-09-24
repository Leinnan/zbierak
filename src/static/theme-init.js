(function () {
  "use strict";

  var storageKey = "zbierak-theme";
  var memoryPreference = "system";
  var media = window.matchMedia("(prefers-color-scheme: dark)");

  function validPreference(value) {
    return value === "light" || value === "dark" || value === "system";
  }

  function preference() {
    try {
      var stored = window.localStorage.getItem(storageKey);
      memoryPreference = validPreference(stored) ? stored : "system";
      return memoryPreference;
    } catch (_) {
      return memoryPreference;
    }
  }

  function resolvedTheme(value) {
    return value === "system" ? (media.matches ? "dark" : "light") : value;
  }

  function configureScalar(value) {
    var element = document.getElementById("api-reference");
    if (!element) return;

    try {
      var config = JSON.parse(element.getAttribute("data-configuration") || "{}");
      config.hideDarkModeToggle = true;
      if (value === "system") {
        delete config.darkMode;
      } else {
        config.darkMode = value === "dark";
      }
      element.setAttribute("data-configuration", JSON.stringify(config));
    } catch (_) {
      // Scalar can still render with its original configuration.
    }
  }

  function apply(value) {
    var selected = validPreference(value) ? value : "system";
    var resolved = resolvedTheme(selected);
    document.documentElement.setAttribute("data-bs-theme", resolved);
    document.documentElement.setAttribute("data-theme-preference", selected);
    document.documentElement.style.colorScheme = resolved;
    configureScalar(selected);
    document.dispatchEvent(new CustomEvent("zbierak:themechange", {
      detail: { preference: selected, theme: resolved }
    }));
  }

  function setPreference(value) {
    var selected = validPreference(value) ? value : "system";
    memoryPreference = selected;
    try {
      window.localStorage.setItem(storageKey, selected);
    } catch (_) {
      // The theme still applies for this page when storage is unavailable.
    }
    apply(selected);
  }

  window.ZbierakTheme = {
    apply: apply,
    get: preference,
    set: setPreference
  };

  apply(preference());

  var onSystemChange = function () {
    if (preference() === "system") apply("system");
  };
  if (media.addEventListener) {
    media.addEventListener("change", onSystemChange);
  } else {
    media.addListener(onSystemChange);
  }

  window.addEventListener("storage", function (event) {
    if (event.key === storageKey) apply(preference());
  });
})();
