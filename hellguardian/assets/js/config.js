/**
 * HellGuardian Client Configuration
 * Supports local execution and persistent cloud hosting via GitHub Pages.
 */
window.HELLGUARDIAN_CONFIG = {
  // Cloud backend API URL. Leave as "" for same-origin local proxy or development server.
  // In production on GitHub Pages, replace with your cloud backend URL, e.g.:
  // API_BASE_URL: "https://hellguardian-api.onrender.com"
  API_BASE_URL: "",

  // Sensor offline threshold in seconds (default 300s = 5 minutes)
  SENSOR_OFFLINE_THRESHOLD_SECONDS: 300,

  // Polling interval for global sensor status badge in milliseconds
  STATUS_POLL_INTERVAL_MS: 30000
};

// Allow runtime override via URL query parameter: ?api=https://my-backend.com
(function () {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const apiParam = urlParams.get("api");
    if (apiParam) {
      window.HELLGUARDIAN_CONFIG.API_BASE_URL = apiParam.replace(/\/+$/, "");
      console.log("[HellGuardian] Active API Base URL overridden via URL parameter:", window.HELLGUARDIAN_CONFIG.API_BASE_URL);
    }
  } catch (err) {
    console.warn("[HellGuardian] Could not parse URL query parameters:", err);
  }
})();
