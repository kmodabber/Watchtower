import { useDevices, useHealth } from "./api/queries";

export default function App() {
  const health = useHealth();
  const devices = useDevices();

  return (
    <div className="layout">
      <header className="header">
        <h1>Watchtower</h1>
        <span className="status">
          {health.isError ? "API unreachable" : health.data?.database_ok ? "Online" : "Loading…"}
        </span>
      </header>
      <main className="content">
        <p>
          {devices.data
            ? `${devices.data.length} devices on your network.`
            : "Loading devices…"}
        </p>
        <p className="muted">Device list, device page and findings.</p>
      </main>
    </div>
  );
}