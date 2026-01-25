from __future__ import annotations

import click


_TAGS = {
    "debug": "[DEBUG]",
    "info": "[INFO]",
    "warn": "[WARN]",
    "error": "[ERROR]",
    "ok": "[OK]",
    "done": "[DONE]",
}

def emit(severity: str, message: str) -> None:
    tag = _TAGS.get(severity.lower(), "[INFO]")
    click.echo(f"{tag} {message}")