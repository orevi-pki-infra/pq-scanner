from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

class SchemaValidationError(Exception):
    def __init__(self, errors: List[Dict[str, str]]):
        super().__init__("Schema validation failed")
        self.errors = errors

def _load_schema(schemas_dir: Path, filename: str) -> Dict[str, Any]:
    p = schemas_dir / filename
    if not p.exists():
        raise FileNotFoundError(f"Schema not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))

def validate_observation(observation: Dict[str, Any], schemas_dir: str | Path) -> List[Dict[str, str]]:
    """Return a list of validation errors; empty list means valid.
    Uses jsonschema if available; otherwise returns an empty list (best-effort mode).
    """
    schemas_dir = Path(schemas_dir)

    try:
        import jsonschema
    except Exception:
        # Best-effort mode if jsonschema isn't installed
        return []

    errors_out: List[Dict[str, str]] = []

    envelope = _load_schema(schemas_dir, "observation-envelope.schema.json")
    surface = observation.get("surface")

    def collect_errors(schema: Dict[str, Any], instance: Dict[str, Any]):
        validator = jsonschema.Draft202012Validator(schema)
        for err in sorted(validator.iter_errors(instance), key=lambda e: e.path):
            path = "$"
            for part in err.path:
                if isinstance(part, int):
                    path += f"[{part}]"
                else:
                    path += f".{part}"
            errors_out.append({"path": path, "message": err.message})

    collect_errors(envelope, observation)

    surface_to_schema = {
        "tls": "observation-tls.schema.json",
        "kms": "observation-kms.schema.json",
        "vault": "observation-vault.schema.json",
        "repo": "observation-repo.schema.json",
        "ssh": "observation-ssh.schema.json",
    }

    if surface not in surface_to_schema:
        errors_out.append({"path": "$.surface", "message": f"Unknown surface '{surface}'"})
        return errors_out

    surface_schema = _load_schema(schemas_dir, surface_to_schema[surface])
    collect_errors(surface_schema, observation)

    return errors_out
