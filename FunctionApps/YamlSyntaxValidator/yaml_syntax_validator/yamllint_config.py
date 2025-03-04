"""Configuration for yamllint integration."""

import os
import yaml
import logging
from typing import Dict, Any
from yamllint.config import YamlLintConfig

# Default yamllint configuration
DEFAULT_YAMLLINT_CONFIG = """
extends: default
rules:
  line-length:
    max: 120
    level: warning
  document-start:
    level: warning
  trailing-spaces: enable
  new-line-at-end-of-file: enable
  empty-lines:
    max: 2
    max-start: 0
    max-end: 1
  indentation:
    spaces: 2
    indent-sequences: true
    check-multi-line-strings: false
  colons:
    max-spaces-before: 0
    max-spaces-after: 1
  commas:
    max-spaces-before: 0
    min-spaces-after: 1
    max-spaces-after: 1
"""

def get_yamllint_config(custom_config: Dict[str, Any] = None) -> YamlLintConfig:
    """
    Get a yamllint configuration.
    
    Args:
        custom_config: Optional dictionary with custom yamllint rules
        
    Returns:
        YamlLintConfig object
    """
    try:
        if custom_config:
            # Convert custom_config dictionary to YAML string
            config_str = yaml.dump(custom_config)
            return YamlLintConfig(content=config_str)
        else:
            # Use the default config
            return YamlLintConfig(content=DEFAULT_YAMLLINT_CONFIG)
    except Exception as e:
        logging.error(f"Error creating yamllint config: {str(e)}")
        # Fall back to built-in default config
        return YamlLintConfig('extends: default')