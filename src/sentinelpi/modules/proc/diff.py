from sentinelpi.modules.proc.models import ProcessRecord


def diff_processes(
    baseline: list[ProcessRecord],
    current: list[ProcessRecord],
) -> dict[str, list[ProcessRecord]]:
    baseline_ids = {p.identity for p in baseline}
    current_ids = {p.identity for p in current}

    new_identities = current_ids - baseline_ids

    new_processes = [
        p for p in current if p.identity in new_identities
    ]

    root_processes = [
        p for p in current if p.user == "root"
    ]

    return {
        "new": new_processes,
        "root": root_processes,
    }

def count_findings(diff: dict[str, list]) -> int:
    return len(diff.get("new", [])) + len(diff.get("root", []))
