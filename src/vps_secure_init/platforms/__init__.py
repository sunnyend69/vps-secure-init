"""Platform detection and capability contracts."""

from .linux import CapabilityError, LinuxCapabilitySnapshot, parse_linux_capabilities, validate_linux_capabilities

__all__ = [
    "CapabilityError",
    "LinuxCapabilitySnapshot",
    "parse_linux_capabilities",
    "validate_linux_capabilities",
]
