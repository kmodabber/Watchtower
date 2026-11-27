import { useSyncExternalStore } from "react";

// Hash routes: FastAPI's StaticFiles has no SPA fallback, so path routes would 404 on reload.
export const deviceHref = (id: number) => `#/devices/${id}`;

const subscribe = (onChange: () => void) => {
  window.addEventListener("hashchange", onChange);
  return () => window.removeEventListener("hashchange", onChange);
};

export const useHash = () => useSyncExternalStore(subscribe, () => window.location.hash);

// "#/devices/<x>" -> "<x>" (unvalidated); null for any other route.
export const deviceRouteId = (hash: string): string | null =>
  hash.match(/^#\/devices\/([^/]*)$/)?.[1] ?? null;
