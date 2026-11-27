import type {
  Change, Consent, Device, DeviceDetail, Finding, Health, Profile,
  Scan, ScanRequest, Score, Severity,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    throw new ApiError(response.status, `${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  health: () => request<Health>("/health"),
  devices: () => request<Device[]>("/devices"),
  device: (id: number) => request<DeviceDetail>(`/devices/${id}`),
  findings: (filters: { severity?: Severity; open?: boolean } = {}) =>
    request<Finding[]>(`/findings${query(filters)}`),
  changes: (filters: { since?: string; limit?: number } = {}) =>
    request<Change[]>(`/changes${query(filters)}`),
  scans: (limit?: number) => request<Scan[]>(`/scans${query({ limit })}`),
  scan: (id: number) => request<Scan>(`/scans/${id}`),
  scores: () => request<Score[]>("/scores"),
  // Writes. No target is ever sent: the scanner uses the configured subnet.
  requestScan: (profile: Profile = "full") =>
    request<ScanRequest>("/scans", { method: "POST", body: JSON.stringify({ profile }) }),
  consent: () =>
    request<Consent>("/consent", {
      method: "POST",
      body: JSON.stringify({ i_own_this_network: true }),
    }),
};