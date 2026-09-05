import { clearTokens, getAccessToken, getRefreshToken, setTokens } from "./auth";
import type {
  AlertOut,
  AlertStatus,
  BlockedIPOut,
  CaseCommentOut,
  CaseOut,
  CaseStatus,
  DetectionRunResult,
  IOCLookupResult,
  MLScoreResult,
  PlaybookRunOut,
  SoarRunResult,
  Token,
  TrainResult,
  UserOut,
} from "./types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  const response = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!response.ok) return false;

  const token: Token = await response.json();
  setTokens(token.access_token, token.refresh_token);
  return true;
}

// One retry, not a general-purpose retry loop: if the token is still
// invalid after a single refresh attempt, the right move is sending the
// user back to login, not retrying indefinitely.
async function apiFetch<T>(path: string, options: RequestInit = {}, isRetry = false): Promise<T> {
  const accessToken = getAccessToken();
  const headers = new Headers(options.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });

  if (response.status === 401 && !isRetry) {
    const refreshed = await refreshAccessToken();
    if (refreshed) return apiFetch<T>(path, options, true);
    clearTokens();
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, body.detail ?? "Request failed");
  }

  // 204/202-with-empty-body endpoints exist elsewhere in this API — guard
  // against calling .json() on a response with no body.
  const text = await response.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

export async function login(email: string, password: string): Promise<Token> {
  const body = new URLSearchParams({ username: email, password });
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Login failed" }));
    throw new ApiError(response.status, err.detail ?? "Login failed");
  }
  return response.json();
}

export async function register(email: string, password: string): Promise<UserOut> {
  return apiFetch<UserOut>("/api/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
}

export async function getCurrentUser(): Promise<UserOut> {
  return apiFetch<UserOut>("/api/v1/auth/me");
}

export async function getAlerts(status?: AlertStatus): Promise<AlertOut[]> {
  const query = status ? `?status=${status}` : "";
  return apiFetch<AlertOut[]>(`/api/v1/detections/alerts${query}`);
}

export async function runDetection(lookbackMinutes = 20): Promise<DetectionRunResult> {
  return apiFetch<DetectionRunResult>(
    `/api/v1/detections/run?lookback_minutes=${lookbackMinutes}`,
    { method: "POST" },
  );
}

export async function getMlMetrics(): Promise<TrainResult> {
  return apiFetch<TrainResult>("/api/v1/ml/metrics");
}

export async function trainMl(): Promise<TrainResult> {
  return apiFetch<TrainResult>("/api/v1/ml/train", { method: "POST" });
}

export async function scoreMl(lookbackMinutes = 60): Promise<MLScoreResult> {
  return apiFetch<MLScoreResult>(`/api/v1/ml/score?lookback_minutes=${lookbackMinutes}`, {
    method: "POST",
  });
}

export async function lookupIOC(ip: string): Promise<IOCLookupResult> {
  return apiFetch<IOCLookupResult>(`/api/v1/threat-intel/${ip}`);
}

export async function getCases(status?: CaseStatus): Promise<CaseOut[]> {
  const query = status ? `?status_filter=${status}` : "";
  return apiFetch<CaseOut[]>(`/api/v1/cases${query}`);
}

export async function getCase(id: string): Promise<CaseOut> {
  return apiFetch<CaseOut>(`/api/v1/cases/${id}`);
}

export async function createCase(payload: {
  title: string;
  summary?: string;
  severity: string;
  tags?: string[];
}): Promise<CaseOut> {
  return apiFetch<CaseOut>("/api/v1/cases", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function updateCase(
  id: string,
  payload: { status?: CaseStatus; tags?: string[] },
): Promise<CaseOut> {
  return apiFetch<CaseOut>(`/api/v1/cases/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function closeCase(id: string): Promise<CaseOut> {
  return apiFetch<CaseOut>(`/api/v1/cases/${id}/close`, { method: "POST" });
}

export async function getCaseComments(caseId: string): Promise<CaseCommentOut[]> {
  return apiFetch<CaseCommentOut[]>(`/api/v1/cases/${caseId}/comments`);
}

export async function addCaseComment(caseId: string, body: string): Promise<CaseCommentOut> {
  return apiFetch<CaseCommentOut>(`/api/v1/cases/${caseId}/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body }),
  });
}

export async function runSoar(): Promise<SoarRunResult> {
  return apiFetch<SoarRunResult>("/api/v1/soar/run", { method: "POST" });
}

export async function getPlaybookRuns(): Promise<PlaybookRunOut[]> {
  return apiFetch<PlaybookRunOut[]>("/api/v1/soar/runs");
}

export async function getBlockedIPs(): Promise<BlockedIPOut[]> {
  return apiFetch<BlockedIPOut[]>("/api/v1/soar/blocked-ips");
}

export { ApiError };
