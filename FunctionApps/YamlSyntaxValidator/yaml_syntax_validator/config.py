"""Configuration constants for the YAML validator."""

MAX_YAML_SIZE = 1024 * 1024  # 1MB
MAX_NESTING_DEPTH = 20
MAX_SEQUENCE_ITEMS = 1000
ALLOWED_TAGS = ["!!str", "!!int", "!!float", "!!bool", "!!null"]