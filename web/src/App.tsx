import DevicePage from "./DevicePage";
import { useDevices, useHealth } from "./api/queries";
import { deviceRouteId, useHash } from "./route";

export default function App() {
  const health = useHealth();
  const deviceId = deviceRouteId(useHash());

  return (
    <div className="layout">
      <header className="header">
        <h1>Watchtower</h1>
        <span className="status">
          {health.isError ? "API unreachable" : health.data?.database_ok ? "Online" : "Loading…"}
        </span>
      </header>
      <main className="content">
        {deviceId === null ? <Home /> : <DevicePage key={deviceId} rawId={deviceId} />}
      </main>
    </div>
  );
}

function Home() {
  const devices = useDevices();
  return (
    <>
      <p>
        {devices.data
          ? `${devices.data.length} devices on your network.`
          : "Loading devices…"}
      </p>
      <p className="muted">Device list, device page and findings.</p>
    </>
  );
}
