import { useQuery } from "@tanstack/react-query";
import { api } from "./client";

export const POLL_MS = 5000; // the dashboard polls every 5 s 

export const useHealth = () =>
  useQuery({ queryKey: ["health"], queryFn: api.health });
export const useDevices = () =>
  useQuery({ queryKey: ["devices"], queryFn: api.devices });
export const useFindings = () =>
  useQuery({ queryKey: ["findings"], queryFn: () => api.findings() });
export const useChanges = () =>
  useQuery({ queryKey: ["changes"], queryFn: () => api.changes() });
export const useScans = () =>
  useQuery({ queryKey: ["scans"], queryFn: () => api.scans() });// null = invalid id: the query stays disabled.
export const useDevice = (id: number | null) =>
  useQuery({
    queryKey: ["devices", id],
    queryFn: () => api.device(id as number),
    enabled: id !== null,
  });
