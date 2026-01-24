"""Pythonic wrapper for module options with attribute-style access."""

from typing import Any, Dict, Iterator, Optional


class ModuleOptions:
    """
    Provides attribute-style access to module options.

    Usage:
        module.options.RHOSTS = "192.168.1.100"
        print(module.options.RHOSTS)
        print(module.options)  # Shows all options
    """

    def __init__(self, module):
        # Use object.__setattr__ to avoid triggering our custom __setattr__
        object.__setattr__(self, '_module', module)
        object.__setattr__(self, '_schema', None)  # Lazy-loaded option schema

    def _get_schema(self) -> Dict[str, Dict]:
        """Lazy-load the options schema."""
        if object.__getattribute__(self, '_schema') is None:
            module = object.__getattribute__(self, '_module')
            object.__setattr__(self, '_schema', module._options_structured())
        return object.__getattribute__(self, '_schema')

    def __getattr__(self, name: str) -> Optional[str]:
        """Get option value by attribute name (e.g., options.RHOSTS)."""
        if name.startswith('_'):
            return object.__getattribute__(self, name)
        module = object.__getattribute__(self, '_module')
        return module._get_option(name)

    def __setattr__(self, name: str, value: Any) -> None:
        """Set option value by attribute name (e.g., options.RHOSTS = "...")."""
        if name.startswith('_'):
            object.__setattr__(self, name, value)
        else:
            module = object.__getattribute__(self, '_module')
            module._set_option(name, str(value))
            # Invalidate schema cache since we modified options
            object.__setattr__(self, '_schema', None)

    def __getitem__(self, name: str) -> Optional[str]:
        """Dict-style access: options["RHOSTS"]."""
        return self.__getattr__(name)

    def __setitem__(self, name: str, value: Any) -> None:
        """Dict-style access: options["RHOSTS"] = "..."."""
        self.__setattr__(name, value)

    def __contains__(self, name: str) -> bool:
        """Check if option exists: "RHOSTS" in options."""
        return name.upper() in (k.upper() for k in self._get_schema().keys())

    def __iter__(self) -> Iterator[str]:
        """Iterate over option names."""
        return iter(self._get_schema().keys())

    def keys(self):
        """Return all option names."""
        return self._get_schema().keys()

    def items(self):
        """Return (name, current_value) pairs."""
        module = object.__getattribute__(self, '_module')
        for name in self._get_schema().keys():
            yield name, module._get_option(name)

    def schema(self) -> Dict[str, Dict]:
        """Get full option schema with types, defaults, descriptions."""
        return self._get_schema()

    def missing_required(self) -> list:
        """Get list of required options that aren't set."""
        module = object.__getattribute__(self, '_module')
        return module._missing_required()

    def __repr__(self) -> str:
        """Pretty-print all options with current values."""
        lines = ["Module Options:"]
        schema = self._get_schema()
        module = object.__getattribute__(self, '_module')

        for name, info in schema.items():
            current = module._get_option(name)
            req = "*" if info.get("required") else " "
            opt_type = info.get("type", "?")
            default = info.get("default", "")
            desc = info.get("desc", "")

            if current:
                value_str = f'= "{current}"'
            elif default:
                value_str = f'(default: "{default}")'
            else:
                value_str = "(not set)"

            lines.append(f"  {req} {name}: {opt_type} {value_str}")
            if desc:
                # Truncate long descriptions
                desc_display = desc[:60] + "..." if len(desc) > 60 else desc
                lines.append(f"      {desc_display}")

        return "\n".join(lines)
