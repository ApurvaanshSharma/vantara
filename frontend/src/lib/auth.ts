// Tokens stored in localStorage — the simple, common SPA pattern, and the
// deliberate trade-off worth naming: localStorage is readable by any JS
// that runs on this origin, so it's vulnerable to XSS in a way an
// httpOnly cookie wouldn't be. The more secure version has the backend
// set httpOnly cookies at login instead of returning tokens in the JSON
// body — a real hardening step for a v2, not implemented here because it
// changes the login endpoint's contract on the backend too, not just the
// frontend storage mechanism.

const ACCESS_TOKEN_KEY = "vantara_access_token";
const REFRESH_TOKEN_KEY = "vantara_refresh_token";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(accessToken: string, refreshToken: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return getAccessToken() !== null;
}
