"""Security validation module for YAML content."""

from dataclasses import dataclass
from typing import List, Optional, Any
import sys, yaml
from ..config import MAX_YAML_SIZE, MAX_NESTING_DEPTH, MAX_SEQUENCE_ITEMS

@dataclass
class SecurityConfig:
    max_size: int = MAX_YAML_SIZE
    max_depth: int = MAX_NESTING_DEPTH
    max_sequence_items: int = MAX_SEQUENCE_ITEMS
    allowed_tags: Optional[List[str]] = None

class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass

def validate_yaml_security(content: str, config: SecurityConfig) -> None:
    """Validate YAML content against security constraints."""
    if len(content.encode('utf-8')) > config.max_size:
        raise SecurityError(f"YAML content exceeds maximum size of {config.max_size} bytes")
    
    if "!!python/object" in content or "!!python/module" in content:
        raise SecurityError("Potentially dangerous YAML tags detected")

def check_nesting_depth(data: Any, current_depth: int = 0) -> int:
    """Recursively check nesting depth of YAML structure."""
    if current_depth > MAX_NESTING_DEPTH:
        raise SecurityError(f"Maximum nesting depth of {MAX_NESTING_DEPTH} exceeded")
    
    if isinstance(data, dict):
        return max((check_nesting_depth(value, current_depth + 1) for value in data.values()), default=current_depth)
    elif isinstance(data, list):
        if len(data) > MAX_SEQUENCE_ITEMS:
            raise SecurityError(f"Maximum sequence items limit of {MAX_SEQUENCE_ITEMS} exceeded")
        return max((check_nesting_depth(item, current_depth + 1) for item in data), default=current_depth)
    return current_depth


def get_deep_size(obj: Any) -> int:
    """Calculate the total size of an object and its nested elements."""
    seen = set()  # Keep track of objects to handle circular references
    
    def sizeof(obj: Any) -> int:
        if obj is None:
            return 0
            
        obj_id = id(obj)
        if obj_id in seen:
            return 0
        seen.add(obj_id)
        
        try:
            size = sys.getsizeof(obj)
            
            if isinstance(obj, dict):
                size += sum(sizeof(k) + sizeof(v) for k, v in obj.items())
            elif isinstance(obj, (list, tuple, set)):
                size += sum(sizeof(item) for item in obj)
            elif hasattr(obj, '__dict__'):
                size += sizeof(obj.__dict__)
            
            return size
        except Exception:
            return 0  # Return 0 if we can't calculate size for this object
    
    return sizeof(obj)

# Update security validation to use the new size calculation
def validate_yaml_security(content: str, config: SecurityConfig) -> None:
    content_size = len(content.encode('utf-8'))
    if content_size > config.max_size:
        raise SecurityError(f"YAML content exceeds maximum size of {config.max_size} bytes")
    
    # Parse and check memory usage
    try:
        data = yaml.safe_load(content)
        if data is not None:
            actual_size = get_deep_size(data)
            if actual_size > config.max_size:
                raise SecurityError(f"Parsed YAML exceeds memory limit of {config.max_size} bytes")
    except yaml.YAMLError:
        pass  # Let the parser handle YAML errors