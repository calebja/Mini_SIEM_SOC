"""
evaluate.py
Scores the Detection Engine's output against the red-team answer key
(ground_truth.json) that generate_logs.py produced. This is the "generate
synthetic attacks and calculate true-positive/false-positive rates" step.

Matching rule: an alert is a true positive for a ground-truth campaign if
they share the same attack_type, their timestamps overlap (with a 2-minute
grace window), and they share a source IP or target host. Every alert that
doesn't match any campaign is a false positive. Every campaign with zero
matching alerts is a false negative (a miss).
"""
import json
import os
import datetime
from collections import defaultdict

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
BUFFER_SECONDS = 120
ts_fmt = "%Y-%m-%d %H:%M:%S"


def to_dt(s):
    return datetime.datetime.strptime(s, ts_fmt)


def overlaps(alert_ts, gt_start, gt_end):
    t = to_dt(alert_ts)
    return (to_dt(gt_start) - datetime.timedelta(seconds=BUFFER_SECONDS)) <= t <= \
           (to_dt(gt_end) + datetime.timedelta(seconds=BUFFER_SECONDS))


def ip_or_host_match(alert, gt):
    gt_ips = set(gt["src_ip"].split("|"))
    alert_ips = set((alert["src_ip"] or "").split("|"))
    if gt_ips & alert_ips:
        return True
    if alert["target_host"] == gt["target_host"]:
        return True
    return False


def main():
    with open(os.path.join(DATA_DIR, "ground_truth.json")) as f:
        gts = json.load(f)
    with open(os.path.join(DATA_DIR, "alerts.json")) as f:
        alerts = json.load(f)

    gt_hits = {gt["attack_id"]: [] for gt in gts}
    fp_alerts = []

    for alert in alerts:
        # Collect every campaign this alert is consistent with, then attribute
        # it to the one whose window it's temporally closest to. A plain
        # first-match-wins rule misattributes alerts when two campaigns of the
        # same type land close together (e.g. two exfil bursts minutes apart
        # on the same host) -- a real correlation-engine pitfall worth
        # handling properly rather than papering over.
        candidates = []
        for gt in gts:
            if gt["attack_type"] != alert["attack_type"]:
                continue
            if not overlaps(alert["ts"], gt["start"], gt["end"]):
                continue
            if not ip_or_host_match(alert, gt):
                continue
            candidates.append(gt)
        if candidates:
            best = min(candidates, key=lambda gt: abs((to_dt(alert["ts"]) - to_dt(gt["start"])).total_seconds()))
            gt_hits[best["attack_id"]].append(alert)
        else:
            fp_alerts.append(alert)

    detected = [gid for gid, hits in gt_hits.items() if hits]
    missed = [gid for gid, hits in gt_hits.items() if not hits]

    tp_alert_count = sum(len(h) for h in gt_hits.values())
    fp_alert_count = len(fp_alerts)
    total_alerts = len(alerts)

    print("=" * 70)
    print("DETECTION SCORECARD")
    print("=" * 70)
    print(f"Ground-truth attack campaigns : {len(gts)}")
    print(f"Detected (recall)             : {len(detected)}/{len(gts)} "
          f"({100*len(detected)/len(gts):.0f}%)")
    print(f"Missed (false negatives)      : {len(missed)} -> {missed}")
    print()
    print(f"Total alerts fired            : {total_alerts}")
    print(f"  - true-positive alerts      : {tp_alert_count} "
          f"({100*tp_alert_count/total_alerts:.0f}%)")
    print(f"  - false-positive alerts     : {fp_alert_count} "
          f"({100*fp_alert_count/total_alerts:.0f}%)")
    precision = tp_alert_count / total_alerts if total_alerts else 0
    recall = len(detected) / len(gts) if gts else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    print(f"Alert-level precision         : {precision:.2f}")
    print(f"Campaign-level recall         : {recall:.2f}")
    print(f"F1                            : {f1:.2f}")

    print()
    print(f"{'attack_type':26s} {'campaigns':>10s} {'detected':>9s} {'alerts':>7s} {'FPs':>5s}")
    by_type = defaultdict(lambda: {"campaigns": 0, "detected": 0, "alerts": 0})
    for gt in gts:
        by_type[gt["attack_type"]]["campaigns"] += 1
        if gt_hits[gt["attack_id"]]:
            by_type[gt["attack_type"]]["detected"] += 1
        by_type[gt["attack_type"]]["alerts"] += len(gt_hits[gt["attack_id"]])
    fp_by_type = defaultdict(int)
    for a in fp_alerts:
        fp_by_type[a["attack_type"]] += 1
    for atype, stats in sorted(by_type.items()):
        print(f"{atype:26s} {stats['campaigns']:>10d} {stats['detected']:>9d} "
              f"{stats['alerts']:>7d} {fp_by_type.get(atype,0):>5d}")

    metrics = {
        "total_campaigns": len(gts),
        "detected_campaigns": len(detected),
        "missed_campaigns": missed,
        "total_alerts": total_alerts,
        "true_positive_alerts": tp_alert_count,
        "false_positive_alerts": fp_alert_count,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "by_type": {k: v for k, v in by_type.items()},
        "false_positives_by_type": dict(fp_by_type),
        "fp_alert_list": fp_alerts,
    }
    with open(os.path.join(DATA_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nWrote {os.path.join(DATA_DIR, 'metrics.json')}")


if __name__ == "__main__":
    main()
