import { ApiError } from "./api/client";
import { useDevice } from "./api/queries";
import type { Change, DeviceDetail, Finding, Port } from "./api/types";

const CHANGE_LABELS: Record<string, string> = {
  new_device: "First seen on your network",
  device_gone: "Left your network",
  new_port: "New port opened",
  port_closed: "Port closed",
  new_finding: "New risk found",
};

const STATUS_LABELS: Record<string, string> = { online: "Online", gone: "Not seen recently" };

const when = (iso: string) => new Date(iso).toLocaleString();

const typeName = (type: string | null) =>
  type && type !== "unknown" ? type.replaceAll("-", " ") : null;

const BackLink = () => (
  <a className="back" href="#/">
    ← All devices
  </a>
);

export default function DevicePage({ rawId }: { rawId: string }) {
  const id = /^[1-9]\d*$/.test(rawId) && Number.isSafeInteger(Number(rawId)) ? Number(rawId) : null;
  const device = useDevice(id);

  if (id === null || (device.error instanceof ApiError && device.error.status === 404)) {
    return (
      <>
        <BackLink />
        <p>Device not found.</p>
      </>
    );
  }
  if (device.data) return <DeviceView device={device.data} />;
  return (
    <>
      <BackLink />
      <p className={device.isError ? undefined : "muted"}>
        {device.isError ? "Couldn't reach Watchtower." : "Loading device…"}
      </p>
    </>
  );
}

// type_confidence is a category code (0 / 0.33 / 0.67 / 1), not a probability: show the nearest word.
const confidenceWord = (value: number) =>
  value >= 0.84 ? "high" : value >= 0.5 ? "medium" : value > 0.16 ? "low" : null;

function DeviceView({ device }: { device: DeviceDetail }) {
  const type = typeName(device.type);
  const word = device.type_confidence === null ? null : confidenceWord(device.type_confidence);
  const confidence = type && word ? ` · ${word} confidence` : "";
  const details: [string, string | null][] = [
    ["IP address", device.ip],
    ["MAC address", device.mac_randomised ? `${device.mac} (private address)` : device.mac],
    ["Maker", device.vendor],
    ["Hostname", device.hostname],
    ["Operating system", device.os_guess],
    ["Status", STATUS_LABELS[device.status] ?? device.status],
    ["First seen", when(device.first_seen)],
    ["Last seen", when(device.last_seen)],
  ];

  return (
    <div className="device-page">
      <BackLink />
      <header className="device-head">
        <h2>{device.name}</h2>
        <p className="muted device-type">{type ? `${type}${confidence}` : "Type unknown"}</p>
        <p className="badges">
          {device.highest_severity && (
            <span className={`badge sev-${device.highest_severity}`}>
              {device.highest_severity} risk
            </span>
          )}
          {device.trusted && <span className="badge">Trusted</span>}
          {device.muted && <span className="badge">Muted</span>}
        </p>
      </header>

      <section>
        <h3>Details</h3>
        <dl className="details">
          {details.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{value || "—"}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section>
        <h3>{type ? `Why we think it's a ${type}` : "What kind of device is this?"}</h3>
        {device.type_reasons.length ? (
          <ul>
            {device.type_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">We don't have any clues about what kind of device this is yet.</p>
        )}
      </section>

      <section>
        <h3>Open ports</h3>
        {device.ports.length ? <Ports ports={device.ports} /> : <p className="muted">No open ports found.</p>}
      </section>

      <section>
        <h3>Risks</h3>
        {device.findings.length ? (
          device.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)
        ) : (
          <p className="muted">No risks found.</p>
        )}
      </section>

      <section>
        <h3>Recent changes</h3>
        {device.changes.length ? (
          <ul className="changes">
            {device.changes.map((change) => (
              <li key={change.id}>
                <time dateTime={change.at}>{when(change.at)}</time> {changeText(change)}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">No changes yet.</p>
        )}
      </section>
    </div>
  );
}

function Ports({ ports }: { ports: Port[] }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Software</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((p) => (
            <tr key={`${p.port}/${p.protocol}`}>
              <td>
                {p.port}/{p.protocol}
              </td>
              <td>{p.service || "—"}</td>
              <td>{[p.product, p.version].filter(Boolean).join(" ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className={finding.closed_at ? "finding closed" : "finding"}>
      <p className="badges">
        <span className={`badge sev-${finding.severity}`}>{finding.severity}</span>
        {finding.closed_at && <span className="badge">Fixed {when(finding.closed_at)}</span>}
      </p>
      <h4>{finding.title}</h4>
      <p>{finding.explanation}</p>
      <p>
        <strong>How to fix:</strong> {finding.fix}
      </p>
    </article>
  );
}

function changeText(change: Change) {
  const label = CHANGE_LABELS[change.kind] ?? change.kind;
  const port = change.detail?.port;
  return typeof port === "number" ? `${label} (port ${port})` : label;
}
