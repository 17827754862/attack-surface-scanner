const TOKEN_KEY = "attack_surface_token";
const API_BASE = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function api(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };
  const response = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...options,
    headers,
  });
  const text = await response.text();
  let data = text;
  try { data = JSON.parse(text); } catch { /* text response */ }
  if (response.status === 401 && path !== "/api/auth/login") {
    clearToken();
    if (window.location.pathname !== "/login") {
      window.location.assign("/login");
    }
  }
  if (!response.ok) {
    throw new Error(data?.detail || data?.error || text || `HTTP ${response.status}`);
  }
  return data;
}

export function eventUrl(taskId) {
  return `${API_BASE}/api/tasks/${taskId}/events?token=${encodeURIComponent(getToken())}`;
}

export async function downloadFile(path, filename) {
  const token = getToken();
  const response = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) {
    throw new Error(`下载失败：HTTP ${response.status}`);
  }
  const objectUrl = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}
