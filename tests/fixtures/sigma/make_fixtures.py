"""Builds the SYNTHETIC Sigma fixtures in this folder (run: python tests/fixtures/sigma/make_fixtures.py).

They reproduce, with invented uids, the two engine behaviours seen on real data:

1. Duplicate delivery (shape of corr-ce729703..., 116.73.165.239 -> wpktesting3):
   3 distinct failed logins, two of them delivered twice with new uids, so the
   brute-force rule (>= 5) fired on 5 records.
2. Early, suppressed spraying finding (shape of the 13 Oct test, 203.0.113.45 -> web-01):
   5 users tried; the spraying finding lists only the first 3, the brute-force
   finding lists all 5.

Also included: an unrelated IP attacking web-01 in the same minute (must not join
the spraying incident), an event whose raw_data is broken (must be rebuilt from the
OCSF columns), a duplicated correlation row and a row without finding_uid.
"""

import json
from pathlib import Path

import pandas as pd

HERE = Path(__file__).parent
NOTE = "SYNTHETIC TEST FIXTURE built by make_fixtures.py; not exported from ClickHouse."
MITRE = {"5710": ["T1110", "T1021.004"], "5760": ["T1110.001", "T1021.004"]}
DESC = {"5710": "sshd: Attempt to login using a non-existent user",
        "5760": "sshd: authentication failed."}


def event(uid, t, host, ip, port, user, pid, invalid, raw_ok=True, ingest_delay_s=1):
    t = pd.Timestamp(t, tz="UTC")
    code = "5710" if invalid else "5760"
    who = f"invalid user {user}" if invalid else user
    log = f"{t:%b} {t.day:>2} {t:%H:%M:%S} {host} sshd[{pid}]: Failed password for {who} from {ip} port {port} ssh2"
    ingest = t + pd.Timedelta(seconds=ingest_delay_s)
    alert = {
        "timestamp": ingest.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {"id": code, "level": 5, "description": DESC[code],
                 "mitre": {"id": MITRE[code]}, "groups": ["syslog", "sshd", "authentication_failed"]},
        "agent": {"id": "007" if host == "web-01" else "003", "name": host},
        "decoder": {"name": "sshd"},
        "data": {"srcip": ip, "srcport": str(port), "srcuser": user},
        "full_log": log,
        "id": f"{int(ingest.timestamp())}.{pid}",
    }
    return {
        "class_uid": 2004, "time": int(ingest.timestamp() * 1000), "time_dt": ingest.isoformat(),
        "message": log, "finding_uid": uid, "finding_title": DESC[code], "rule_id": code,
        "device_hostname": host, "device_uid": alert["agent"]["id"], "user_name": user,
        "src_ip": ip, "src_port": port, "attacks": "[]",
        "raw_data": json.dumps(alert) if raw_ok else "{not valid json",
    }


def correlation(uid, rule_id, title, ip, host, uids, first, last, group_key):
    return {
        "time": int(pd.Timestamp(last, tz="UTC").timestamp() * 1000), "finding_uid": uid,
        "finding_title": title, "rule_id": rule_id, "device_hostname": host, "src_ip": ip,
        "group_key": json.dumps(group_key), "contributing_event_count": len(uids),
        "first_seen_time": first, "last_seen_time": last,
        "contributing_finding_uids": uids, "attacks": "[]",
    }


# 1. duplicate delivery --------------------------------------------------------------
IP1, H1 = "116.73.165.239", "wpktesting3"
dup_events = []
for i, (t, port, pid) in enumerate([("2026-09-27 12:42:21", 40112, 2201),
                                    ("2026-09-27 12:42:34", 40130, 2205),
                                    ("2026-09-27 12:44:32", 40188, 2219)]):
    dup_events.append(event(f"dup-{i}a", t, H1, IP1, port, "ubuntu", pid, False))
    if i < 2:  # redelivered: same log line, new uid, ingested a few seconds later
        dup_events.append(event(f"dup-{i}b", t, H1, IP1, port, "ubuntu", pid, False, ingest_delay_s=4))
dup_corr = correlation("corr-dup-0001", "multiple_ssh_auth_failures", "Multiple SSH Authentication Failures",
                       IP1, H1, [e["finding_uid"] for e in dup_events],
                       "2026-09-27T12:42:22Z", "2026-09-27T12:44:33Z",
                       {"src_endpoint.ip": IP1, "device.hostname": H1})

# 2. spraying -------------------------------------------------------------------------
IP2, H2 = "203.0.113.45", "web-01"
users = [("admin", True), ("root", False), ("ubuntu", False), ("oracle", True), ("test", True)]
spray_events = [event(f"spray-{u}", f"2026-10-13 18:06:{i * 5:02d}", H2, IP2, 50100 + i, u, 4100 + i, inv)
                for i, (u, inv) in enumerate(users)]
spray_corr = correlation("corr-spray-0001", "pwd-spray-cor-1", "SSH Password Spraying", IP2, None,
                         [e["finding_uid"] for e in spray_events[:3]],
                         "2026-10-13T18:06:01Z", "2026-10-13T18:06:11Z", {"src_endpoint.ip": IP2})
spray_corr["device_hostname"] = ""
brute_corr = correlation("corr-brute-0001", "multiple_ssh_auth_failures", "Multiple SSH Authentication Failures",
                         IP2, H2, [e["finding_uid"] for e in spray_events],
                         "2026-10-13T18:06:01Z", "2026-10-13T18:06:21Z",
                         {"src_endpoint.ip": IP2, "device.hostname": H2})
# unrelated attacker on the same host, same minute; its raw_data is broken
noise = [event("noise-1", "2026-10-13 18:06:07", H2, "198.51.100.7", 61000, "admin", 4200, True, raw_ok=False),
         event("noise-2", "2026-10-13 18:06:13", H2, "198.51.100.7", 61002, "root", 4201, False)]

correlations = [dup_corr, spray_corr, brute_corr, dict(brute_corr),            # duplicated row
                {**spray_corr, "finding_uid": ""}]                              # malformed row
events = dup_events + spray_events + noise

if __name__ == "__main__":
    for name, data in [("correlations.json", correlations), ("ocsf_events.json", events)]:
        (HERE / name).write_text(json.dumps({"_note": NOTE, "data": data}, indent=1), encoding="utf-8")
    print(f"wrote {len(correlations)} correlations, {len(events)} events")
