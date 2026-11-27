# Watchtower dashboard

React + Vite + TypeScript (strict). It reads the Watchtower API (contract C4)
and polls it every 5 seconds.

## Commands (run in `web/`)

- `npm ci`: install exactly what `package-lock.json` lists
- `npm run dev`: dev server on http://localhost:5173, proxying `/api` to http://127.0.0.1:8000
- `npm run lint`: eslint (no `fetch` outside `src/api/client.ts`)
- `npm run typecheck`: TypeScript check
- `npm run build`: production build into `web/dist`, which the FastAPI app serves at `/`

## Layout

- `src/api/types.ts`: C4 response types
- `src/api/client.ts`: the only file that calls `fetch`
- `src/api/queries.ts`: TanStack Query hooks, used by components