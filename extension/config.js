// URL Guard - settings you may need to change.
// Plain ES module: imported by the service worker, the pages and the Node tests.

// ===================================================================
// The live API on Render (base URL, WITHOUT a trailing slash).
// This is the DEFAULT. A URL saved on the Settings page wins over it;
// "Use default" on the Settings page goes back to this one.
// ===================================================================
export const RENDER_API_BASE = "https://malicious-url-api.onrender.com";

export const LOCAL_API_BASE = "http://localhost:8000";
// The mock server in dev/mock_api.mjs (127.0.0.1, not localhost: the mock only listens on IPv4).
export const MOCK_API_BASE = "http://127.0.0.1:8765";

export const DEFAULT_API_BASE = RENDER_API_BASE;

// Buttons shown on the Settings page.
export const API_PRESETS = [
  { id: "render", label: "Render (default)", url: RENDER_API_BASE },
  { id: "local", label: "Local (" + LOCAL_API_BASE + ")", url: LOCAL_API_BASE },
  { id: "mock", label: "Mock for testing (" + MOCK_API_BASE + ")", url: MOCK_API_BASE },
];

export const TIMEOUTS = {
  predictMs: 5000, // automatic check of a page; after this we FAIL OPEN
  healthMs: 3000, // popup status line
  popupFirstTryMs: 5000, // popup "Check" button, first attempt
  popupRetryTryMs: 15000, // later attempts while the server wakes up
  popupTotalMs: 60000, // the free Render server can take ~60 s to wake up
};

export const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes
export const CACHE_MAX_ENTRIES = 2000;
export const HISTORY_MAX = 50;
export const MAX_BLOCK_RULES = 1000; // declarativeNetRequest redirect rules
export const MAX_URL_LENGTH = 2048;
export const MAX_REASONS_SHOWN = 3;

// Saved settings are merged on top of these defaults.
export const DEFAULT_SETTINGS = { apiBase: DEFAULT_API_BASE, protection: true };
