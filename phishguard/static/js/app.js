/**
 * PHISHGUARD - Client-side Interactive Behaviors
 * Handles real-time validation, preset loading, copy to clipboard, and UI ergonomics.
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. URL Input & Character Counter
  const urlInput = document.getElementById("url-input");
  const charCounter = document.getElementById("char-counter");
  const clearBtn = document.getElementById("clear-btn");
  const scanForm = document.getElementById("scan-form");

  if (urlInput && charCounter) {
    const updateCounter = () => {
      const len = urlInput.value.length;
      charCounter.textContent = `${len} / 2048 chars`;
      if (len > 2048) {
        charCounter.style.color = "var(--phishing-color)";
      } else if (len > 120) {
        charCounter.style.color = "var(--suspicious-color)";
      } else {
        charCounter.style.color = "var(--text-muted)";
      }
    };

    urlInput.addEventListener("input", updateCounter);
    updateCounter();
  }

  // 2. Clear Button Handler
  if (clearBtn && urlInput) {
    clearBtn.addEventListener("click", () => {
      urlInput.value = "";
      urlInput.focus();
      if (charCounter) {
        charCounter.textContent = "0 / 2048 chars";
        charCounter.style.color = "var(--text-muted)";
      }
    });
  }

  // 3. Quick Preset Pills Fill
  const presetPills = document.querySelectorAll(".preset-pill");
  presetPills.forEach((pill) => {
    pill.addEventListener("click", () => {
      const targetUrl = pill.getAttribute("data-url");
      if (targetUrl && urlInput) {
        urlInput.value = targetUrl;
        if (charCounter) {
          charCounter.textContent = `${targetUrl.length} / 2048 chars`;
        }
        urlInput.focus();
        // Optional smooth scroll to input if on mobile
        urlInput.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    });
  });

  // 4. Form Submit Guard (Defensive client-side validation)
  if (scanForm && urlInput) {
    scanForm.addEventListener("submit", (e) => {
      const val = urlInput.value.trim();
      if (!val) {
        e.preventDefault();
        alert("Please enter a URL to inspect.");
        urlInput.focus();
        return false;
      }
      if (val.length > 2048) {
        e.preventDefault();
        alert("The entered URL exceeds the maximum allowed length of 2048 characters.");
        return false;
      }
    });
  }

  // 5. Copy URL to Clipboard
  const copyButtons = document.querySelectorAll(".btn-copy");
  copyButtons.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = btn.getAttribute("data-copy");
      if (text) {
        try {
          await navigator.clipboard.writeText(text);
          const originalText = btn.innerHTML;
          btn.innerHTML = "<span>Copied!</span>";
          btn.style.borderColor = "var(--safe-color)";
          setTimeout(() => {
            btn.innerHTML = originalText;
            btn.style.borderColor = "";
          }, 1800);
        } catch (err) {
          console.error("Clipboard copy failed: ", err);
        }
      }
    });
  });

  // 6. Real-time History Table Search Filter
  const historySearch = document.getElementById("history-search");
  const historyRows = document.querySelectorAll(".history-row");
  if (historySearch && historyRows.length > 0) {
    historySearch.addEventListener("input", (e) => {
      const term = e.target.value.toLowerCase().trim();
      historyRows.forEach((row) => {
        const urlText = row.getAttribute("data-url") || "";
        const hostText = row.getAttribute("data-host") || "";
        const classText = row.getAttribute("data-class") || "";
        if (
          urlText.toLowerCase().includes(term) ||
          hostText.toLowerCase().includes(term) ||
          classText.toLowerCase().includes(term)
        ) {
          row.style.display = "";
        } else {
          row.style.display = "none";
        }
      });
    });
  }

  // 7. Auto-dismiss flash notifications after 5 seconds
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alertEl) => {
    setTimeout(() => {
      alertEl.style.transition = "opacity 0.4s ease";
      alertEl.style.opacity = "0";
      setTimeout(() => alertEl.remove(), 400);
    }, 5000);
  });
});

/**
 * Global confirmation dialog helper for destructive actions.
 */
function confirmClearHistory() {
  return confirm(
    "Are you sure you want to permanently clear all scan history from the SQLite database? This action cannot be undone."
  );
}
