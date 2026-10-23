"""Rule registry: built-in rules plus optional custom YAML rules."""

from __future__ import annotations

from skillfuse.core.config import ScanConfig
from skillfuse.rules import (
    dependencies,
    exfiltration,
    hidden_content,
    metadata,
    network,
    prompt_injection,
    shell,
    tool_overreach,
)
from skillfuse.rules.base import RegexRule, Rule, RuleContext, RuleDescriptor, RuleRegistry
from skillfuse.rules.custom import load_custom_rules

BUILTIN_RULES: tuple[Rule, ...] = (
    *prompt_injection.RULES,
    *hidden_content.RULES,
    *exfiltration.RULES,
    *shell.RULES,
    *network.RULES,
    *tool_overreach.RULES,
    *dependencies.RULES,
    *metadata.RULES,
)


def default_registry() -> RuleRegistry:
    return RuleRegistry(BUILTIN_RULES)


def registry_for(config: ScanConfig) -> RuleRegistry:
    registry = default_registry()
    for rel in config.rules_dirs:
        path = config.resolve(rel)
        if path is not None and path.exists():
            for rule in load_custom_rules([path]):
                registry.register(rule)
    return registry.without(config.disabled_rules)


__all__ = [
    "BUILTIN_RULES",
    "RegexRule",
    "Rule",
    "RuleContext",
    "RuleDescriptor",
    "RuleRegistry",
    "default_registry",
    "load_custom_rules",
    "registry_for",
]
