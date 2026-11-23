"""Summarize paired trials; reject missing data and retain the 90% direct gate."""

import math
from pathlib import Path
import re
import statistics
import sys


def summarize(directory):
    samples = {}
    heading = re.compile(r"^BenchmarkTransferRate(Baseline)?/(scp_upload|ssh_stream)-\d+\s+(.*)$")
    result = re.compile(r"^\s*\d+\s+\d+\s+ns/op\s+([\d.]+)\s+MB/s\s*$")
    for daemon in ("go", "rust", "direct"):
        for trial in range(1, 7):
            path = directory / f"{daemon}-{trial}.log"
            found = []
            pending = None
            for line in path.read_text(encoding="utf-8").splitlines():
                match = heading.match(line)
                if match:
                    if pending is not None:
                        raise ValueError(f"{path}: benchmark has no result")
                    baseline, case, line = match.groups()
                    pending = (baseline, case)
                match = result.match(line)
                if match:
                    if pending is None:
                        raise ValueError(f"{path}: result has no benchmark name")
                    found.append((*pending, match[1]))
                    pending = None
            if pending is not None:
                raise ValueError(f"{path}: benchmark has no result")
            if len(found) != 2 or {case for _, case, _ in found} != {"scp_upload", "ssh_stream"}:
                raise ValueError(f"{path}: expected exactly one result per workload")
            for baseline, case, speed in found:
                speed = float(speed)
                if bool(baseline) != (daemon == "direct") or not math.isfinite(speed) or speed <= 0:
                    raise ValueError(f"{path}: invalid benchmark result")
                samples[daemon, trial, case] = speed

    lines = [
        "## Same-runner Go/Rust comparison",
        "",
        "Six alternating trials, identical OpenSSH client/server, plugins and workload.",
        "Rates are medians; ratios are medians of paired trials, not ratios of medians.",
        "",
        "| Workload | Go MB/s | Rust MB/s | Direct MB/s | Rust / Go | Paired range | Rust / direct | Go / direct |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    passed = True
    for case in ("scp_upload", "ssh_stream"):
        rates = {
            daemon: [samples[daemon, trial, case] for trial in range(1, 7)]
            for daemon in ("go", "rust", "direct")
        }
        paired = [rust / go * 100 for rust, go in zip(rates["rust"], rates["go"])]
        direct = {
            daemon: statistics.median(
                speed / base * 100 for speed, base in zip(rates[daemon], rates["direct"])
            )
            for daemon in ("go", "rust")
        }
        passed &= all(value >= 90 for value in direct.values())
        lines.append(
            f"| {case} | {statistics.median(rates['go']):.2f}"
            f" | {statistics.median(rates['rust']):.2f}"
            f" | {statistics.median(rates['direct']):.2f}"
            f" | {statistics.median(paired):.1f}%"
            f" | {min(paired):.1f}-{max(paired):.1f}%"
            f" | {direct['rust']:.1f}% | {direct['go']:.1f}% |"
        )
    lines += [
        "",
        "Above 100% in Rust / Go favors Rust. A range crossing 100% is mixed evidence.",
        "This is throughput including connection setup, not a CPU/memory or concurrency benchmark.",
    ]
    return "\n".join(lines), passed


if __name__ == "__main__":
    summary, passed = summarize(Path(sys.argv[1]))
    print(summary)
    if not passed:
        sys.exit("Paired median throughput fell below the existing 90% direct-SSH gate")
