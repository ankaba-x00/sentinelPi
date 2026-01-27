from sentinelpi.modules.fs.models import FileRecord


def diff_files(
    baseline: list[FileRecord],
    current: list[FileRecord],
) -> dict[str, list[FileRecord]]:
    base_map = {f.identity: f for f in baseline}
    curr_map = {f.identity: f for f in current}

    modified = []
    new = []
    deleted = []

    for path, curr in curr_map.items():
        if path not in base_map:
            new.append(curr)
        else:
            base = base_map[path]
            if base.sha256 != curr.sha256:
                modified.append(curr)

    for path, base in base_map.items():
        if path not in curr_map:
            deleted.append(base)

    return {
        "modified": modified,
        "new": new,
        "deleted": deleted,
    }

def count_findings(diff: dict[str, list]) -> int:
    return (
        len(diff.get("modified", []))
        + len(diff.get("new", []))
        + len(diff.get("deleted", []))
    )

