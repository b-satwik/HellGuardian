# HellGuardian Cyberpunk Dashboard Architecture & Deployment Guide

This document describes the design language preservation, directory structure, page-loader routing, API consumption schemas, and production deployment instructions for the **HellGuardian Cyberpunk Dashboard** (Apache Frontend).

---

## 1. Directory Structure (Apache Compliant)

All client assets are relative-pathed and organized in a production-ready package under `/home/balasatwik/AdaptiveCowrie/hellguardian/`:

```
hellguardian/
│
├── index.html           # Main Single Page App container (Vignettes, Boot Terminal)
│
├── assets/              # Relative global assets
│   ├── css/
│   │   └── style.css    # Cinematic dark grid background, scroll bars, CRT vignette
│   └── js/
│       └── app.js       # Background dust particles, typewriter boot log, AJAX view swap
│
└── pages/               # Dynamically enqueued AJAX sub-page modules
    ├── cowrie.html      # SSH command grids and terminal timelines
    ├── suricata.html    # IDS alert categories and packet statistics
    ├── heralding.html   # credential spraying trackers
    ├── dionaea.html     # malware download family tables
    ├── conpot.html      # ICS modbus registers
    ├── sandbox.html     # process spawn report tables
    ├── ml.html          # XGBoost SHAP waterfall charts
    ├── graph.html       # D3.js force-directed knowledge graph
    ├── reports.html     # LLM briefings markdown exports
    └── settings.html    # config toggles
```

All references are written as relative paths (`./assets/`, `pages/`), permitting copy-paste deployment directly into Apache's document root directory without code edits.

---

## 2. Visual Identity Preservation (Design System)

The user portfolio style has been integrated into the dashboard HUD interface:
- **Dark Grid Theme**: Employs the identical color palette (`#020105` raw, `#05020a` primary, `#0d0718` secondary) with neon glow accents (`#00ff66` green, `#00f0ff` cyan, `#b624ff` purple).
- **CRT overlays**: Overlay filters (`.crt-overlay`, `.crt-vignette`) simulate a command-console CRT display grid.
- **Typewriter Terminal boot**: The landing page prompts visitors with an ASCII "HELLGUARDIAN" system boot terminal screen, logging decrypter files loading, and fading out only upon clicking `DECRYPT_INTELLIGENCE.SH`.
- **Canvas Particles**: A background engine (`#particle-canvas`) renders drifting vector dust particles continuously behind the cards layout.

---

## 3. Production Apache Deployment Steps

To serve the HellGuardian dashboard as the primary interface via Apache HTTP server:

1. **Verify Apache Installation**:
   Ensure Apache is installed and running on the host system:
   ```bash
   sudo systemctl status apache2
   ```
2. **Copy Frontend Directory**:
   Copy the entire `hellguardian/` workspace folder into Apache's document root `/var/www/html/`:
   ```bash
   sudo cp -r /home/balasatwik/AdaptiveCowrie/hellguardian /var/www/html/
   ```
3. **Configure Permissions**:
   Assure directories and files are owned by the `www-data` user:
   ```bash
   sudo chown -r www-data:www-data /var/www/html/hellguardian
   sudo chmod -r 755 /var/www/html/hellguardian
   ```
4. **Apache VirtualHost Mapping (Optional)**:
   To make HellGuardian the root index, edit `/etc/apache2/sites-available/000-default.conf` and update the `DocumentRoot`:
   ```apache
   DocumentRoot /var/www/html/hellguardian
   ```
   Restart Apache:
   ```bash
   sudo systemctl restart apache2
   ```

---

## 4. Single Page AJAX Router & Hooks

In `assets/js/app.js`, view routing is handled using data attributes and dynamic string injection:
```javascript
function switchView(viewName) {
  fetch(`./pages/${viewName}.html`)
    .then(res => res.text())
    .then(html => {
      document.getElementById("view-container").innerHTML = html;
      initPageScripts(viewName); // Binds charts and maps
    });
}
```
This preserves the background particles and CRT vignettes since the parent `index.html` is never reloaded.

---

## 5. Adding Future Modules

To append a new page to the HUD while maintaining the design language:
1. **Append Navigation Entry**: Add a new list item under `.nav-links ul` inside `index.html`:
   ```html
   <li data-view="new_module">NEW MODULE</li>
   ```
2. **Create Sub-Page**: Create `new_module.html` under `pages/` containing only the HTML fragment for your cards or table structures.
3. **Configure AJAX hook**: Inside `assets/js/app.js`, update the switch view statement to load dynamic backend telemetry APIs for `new_module`.
4. **Preserve Spacing**: Wrap panels in `.stat-card` or `.detail-panel` classes to inherit border glows, Outfit typography, and Fira Code log grids automatically.
