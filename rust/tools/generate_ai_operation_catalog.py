#!/usr/bin/env python3
"""Snapshot AI-edit operation schemas for the Rust engine.

The canonical models remain generated from Java's OpenAPI document in
``engine/src/stirling/models/tool_models.py``. This script imports only those
models (without importing the Python engine application) and writes the
self-contained JSON schemas consumed by Rust at compile time.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
STIRLING_ROOT = REPOSITORY_ROOT / "engine" / "src" / "stirling"
OUTPUT = REPOSITORY_ROOT / "rust" / "crates" / "stirling-ai-engine" / "src" / "operation_catalog.json"


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_operations() -> dict[object, type[object]]:
    stirling = types.ModuleType("stirling")
    stirling.__path__ = [str(STIRLING_ROOT)]  # type: ignore[attr-defined]
    sys.modules["stirling"] = stirling
    models = types.ModuleType("stirling.models")
    models.__path__ = [str(STIRLING_ROOT / "models")]  # type: ignore[attr-defined]
    sys.modules["stirling.models"] = models
    load_module("stirling.models.base", STIRLING_ROOT / "models" / "base.py")
    tool_models = load_module(
        "stirling.models.tool_models",
        STIRLING_ROOT / "models" / "tool_models.py",
    )
    return tool_models.OPERATIONS


def main() -> None:
    operations = load_operations()
    catalog = {
        str(endpoint): model.model_json_schema(by_alias=True)
        for endpoint, model in sorted(operations.items(), key=lambda item: str(item[0]))
    }
    OUTPUT.write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(catalog)} operation schemas to {OUTPUT}")


if __name__ == "__main__":
    main()
