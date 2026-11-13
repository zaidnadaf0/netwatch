"""Detection module for NetWatch."""

from .rules import DetectionRule, DetectionEngine, get_default_rules

__all__ = ["DetectionRule", "DetectionEngine", "get_default_rules"]