from __future__ import annotations

import importlib

from security_framework.plugins.base import SecurityCheck


def load_check(path: str) -> SecurityCheck:
    module_name, class_name = path.rsplit(".", 1)
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    instance = cls()
    if not isinstance(instance, SecurityCheck):
        raise TypeError(f"Plugin {path} is not a SecurityCheck")
    return instance


def load_checks(paths: list[str]) -> list[SecurityCheck]:
    return [load_check(path) for path in paths]
