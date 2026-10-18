import fnmatch
import logging
import os
import re
import time

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("egress_whitelist")


class DomainMatcher:
    def __init__(self, config_path: str, check_interval_seconds: float = 2.0):
        self.config_path = config_path
        self.check_interval_seconds = check_interval_seconds
        self.last_check_time = 0.0
        self.last_mtime = 0.0
        self.rules: list[str] = []
        self.default_action = "block"
        self._load_config(force=True)

    def _parse_yaml_or_fallback(self, content: str) -> dict:
        """Parses YAML if PyYAML is available, otherwise uses a robust fallback parser."""
        if yaml:
            return yaml.safe_load(content) or {}

        # Fallback simple parser for environments without PyYAML
        # Basic syntax sanity checks
        if content.count("[") != content.count("]") or content.count("{") != content.count("}"):
            raise ValueError("Malformed YAML: mismatched brackets/braces")

        data = {"whitelist": [], "settings": {}}
        current_section = None

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped == "whitelist:":
                current_section = "whitelist"
                continue
            elif stripped == "settings:":
                current_section = "settings"
                continue

            if current_section == "whitelist":
                if stripped.startswith("-"):
                    val = stripped[1:].strip().strip("\"'")
                    if val:
                        data["whitelist"].append(val)
            elif current_section == "settings":
                if ":" in stripped:
                    k, v = stripped.split(":", 1)
                    k = k.strip()
                    v = v.split("#")[0].strip().strip("\"'")
                    data["settings"][k] = v

        return data

    def _load_config(self, force: bool = False) -> bool:
        try:
            if not os.path.exists(self.config_path):
                logger.warning("Whitelist config file not found: %s", self.config_path)
                return False

            mtime = os.path.getmtime(self.config_path)
            if not force and mtime == self.last_mtime:
                return False

            with open(self.config_path, "r", encoding="utf-8") as f:
                content = f.read()

            data = self._parse_yaml_or_fallback(content)

            raw_rules = data.get("whitelist", [])
            normalized_rules = [
                r.strip().lower()
                for r in raw_rules
                if isinstance(r, str) and r.strip()
            ]

            settings = data.get("settings", {})
            self.default_action = settings.get("default_action", "block")
            if "reload_check_seconds" in settings:
                try:
                    self.check_interval_seconds = float(settings["reload_check_seconds"])
                except (ValueError, TypeError):
                    pass

            self.rules = normalized_rules
            self.last_mtime = mtime
            logger.info("Loaded %d whitelist rule(s) from %s", len(self.rules), self.config_path)
            return True
        except Exception as e:
            logger.error("Error reading whitelist config %s: %s (keeping existing rules)", self.config_path, e)
            return False

    def reload_if_needed(self) -> bool:
        now = time.time()
        if now - self.last_check_time >= self.check_interval_seconds:
            self.last_check_time = now
            return self._load_config(force=False)
        return False

    @staticmethod
    def extract_hostname(target: str) -> str:
        if not target:
            return ""
        host = target.strip().lower()
        # Strip scheme if present
        if "://" in host:
            host = host.split("://", 1)[1]
        # Strip path or query if present
        if "/" in host:
            host = host.split("/", 1)[0]
        # Strip port (handle IPv4/domain:port or IPv6 [::1]:port)
        if host.startswith("[") and "]" in host:
            host = host[1:].split("]", 1)[0]
        elif ":" in host:
            host = host.split(":", 1)[0]
        return host

    def is_allowed(self, target: str) -> bool:
        self.reload_if_needed()
        hostname = self.extract_hostname(target)
        if not hostname:
            return False

        for pattern in self.rules:
            if pattern == hostname or fnmatch.fnmatch(hostname, pattern):
                return True
        return self.default_action == "allow"
