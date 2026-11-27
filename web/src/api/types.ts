export type Severity = "high" | "medium" | "low" | "info";
export type Profile = "quick" | "full";

export interface Health {
  status: "ok";
  database_ok: boolean;
  last_scan_at: string | null;
  ownership_confirmed: boolean;
}

export interface Device {
  id: number;
  name: string;
  mac: string;
  ip: string | null;
  vendor: string | null;
  hostname: string | null;
  type: string | null;
  type_confidence: number | null;
  status: string;
  trusted: boolean;
  muted: boolean;
  first_seen: string;
  last_seen: string;
  highest_severity: Severity | null;
  open_findings: number;
}

export interface Port {
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
}

export interface Finding {
  id: number;
  device_id: number;
  rule_id: string;
  port: number | null;
  severity: Severity;
  title: string;
  explanation: string;
  fix: string;
  first_seen: string;
  last_seen: string;
  closed_at: string | null;
}

export interface Change {
  id: number;
  scan_id: number;
  device_id: number;
  kind: string;
  detail: Record<string, unknown> | null;
  at: string;
  alerted_at: string | null;
}

export interface DeviceDetail extends Device {
  mac_randomised: boolean;
  os_guess: string | null;
  friendly_name: string | null;
  user_name: string | null;
  type_reasons: string[];
  ports: Port[];
  findings: Finding[];
  changes: Change[];
}

export interface Scan {
  id: number;
  profile: Profile;
  trigger: string;
  subnet: string;
  nmap_version: string | null;
  started_at: string;
  finished_at: string | null;
  status: string;
  error: string | null;
}

export interface ScanRequest {
  id: number;
  profile: Profile;
  requested_at: string;
  picked_up_at: string | null;
  scan_id: number | null;
}

export interface Consent {
  ownership_confirmed: boolean;
  confirmed_at: string | null;
}

export interface Score {
  scan_id: number;
  at: string;
  device_id: number | null; // null = whole network
  score: number;
}