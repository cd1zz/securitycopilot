"""YAML parsing module with failsafe error handling."""
import re
import yaml
import sys
import traceback
from typing import Dict, Any, Tuple, List
from ..security.validator import SecurityConfig, SecurityError, validate_yaml_security, check_nesting_depth
from ..analysis.statistics import get_structure_info, get_best_practices, get_yaml_statistics
from ..errors.error_handler import parse_yaml_error, get_detailed_error

def collect_yaml_errors(content: str) -> List[Dict[str, Any]]:
    """Collect all YAML errors in the content using line-by-line analysis."""
    errors = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        if not line.strip() or line.strip().startswith('#'):
            continue

        # Check for tabs
        if '\t' in line:
            error_details = {
                "line": i + 1,
                "column": line.index('\t') + 1,
                "error_type": "IndentationError",
                "message": "Tab character found in indentation. Replace the tab with spaces and use an editor that automatically converts tabs to spaces.",
                "context": [
                    f"   {i}: {lines[max(0, i-1)]}", 
                    f"-> {i+1}: {line}",
                    f"   {i+2}: {lines[min(len(lines)-1, i+1)]}"
                ],
                "code_context": {
                    "lines": [
                        lines[max(0, i-1)], 
                        line, 
                        lines[min(len(lines)-1, i+1)]
                    ],
                    "start_line": max(0, i),
                    "problematic_line": i + 1,
                    "problematic_column": line.index('\t') + 1
                }
            }
            errors.append(error_details)
        
        # Check indentation consistency
        leading_spaces = len(line) - len(line.lstrip())
        if leading_spaces % 2 != 0:
            error_details = {
                "line": i + 1,
                "column": 1,
                "error_type": "IndentationError",
                "message": "Indentation must be a multiple of 2 spaces. Check the lines above and below for proper alignment.",
                "context": [
                    f"   {i}: {lines[max(0, i-1)]}", 
                    f"-> {i+1}: {line}",
                    f"   {i+2}: {lines[min(len(lines)-1, i+1)]}"
                ],
                "code_context": {
                    "lines": [
                        lines[max(0, i-1)], 
                        line, 
                        lines[min(len(lines)-1, i+1)]
                    ],
                    "start_line": max(0, i),
                    "problematic_line": i + 1,
                    "problematic_column": 1
                }
            }
            errors.append(error_details)
    
    # Parse incrementally for structural errors
    accumulated = ""
    for i, line in enumerate(lines):
        accumulated += line + '\n'
        try:
            yaml.safe_load(accumulated)
        except yaml.YAMLError as e:
            if hasattr(e, 'problem_mark'):
                # Only add error if it's on the current line
                if e.problem_mark.line == i:
                    error_details = get_detailed_error(e, content)
                    # Avoid duplicate errors
                    if not any(
                        err.get('line') == error_details.get('line') and 
                        err.get('error_type') == error_details.get('error_type')
                        for err in errors
                    ):
                        errors.append(error_details)

    return errors

def parse_yaml(content: str, security_config: SecurityConfig) -> Tuple[bool, Dict[str, Any]]:
    """Parse YAML content with comprehensive error handling."""
    try:
        # Security validation
        try:
            validate_yaml_security(content, security_config)
        except SecurityError as se:
            return False, {
                "error": se,
                "error_type": "SecurityError",
                "message": str(se),
                "content": content
            }
        
        # First collect all syntax errors
        all_errors = collect_yaml_errors(content)
        if all_errors:
            return False, {
                "error": "Multiple YAML errors found",
                "error_type": "YAMLError",
                "all_errors": all_errors,
                "error_count": len(all_errors),
                "content": content
            }

        # If no syntax errors, try full parsing
        try:
            data = yaml.safe_load(content)
            
            # Handle None result
            if data is None:
                return False, {
                    "error": ValueError("Empty YAML content"),
                    "error_type": "EmptyContent",
                    "message": "YAML content is empty or only contains comments",
                    "content": content
                }
                
            # Depth check
            try:
                check_nesting_depth(data)
            except SecurityError as de:
                return False, {
                    "error": de,
                    "error_type": "DepthError",
                    "message": str(de),
                    "content": content
                }
            
            # Memory usage check
            current_memory = sys.getsizeof(data)
            if current_memory > security_config.max_size:
                return False, {
                    "error": SecurityError(f"Parsed YAML exceeds memory limit of {security_config.max_size} bytes"),
                    "error_type": "MemoryError",
                    "message": f"Memory usage ({current_memory} bytes) exceeds limit ({security_config.max_size} bytes)",
                    "content": content
                }
            
            # If we get here, the YAML is valid
            return True, {
                "data": data,
                "structure": get_structure_info(data),
                "suggestions": get_best_practices(content),
                "statistics": get_yaml_statistics(content),
                "content": content,
                "message": "YAML validation successful"
            }
            
        except yaml.YAMLError as ye:
            error_details = get_detailed_error(ye, content)
            return False, {
                "error": ye,
                "error_type": "YAMLError",
                "error_details": error_details,
                "message": str(ye),
                "content": content
            }
            
    except Exception as e:
        return False, {
            "error": e,
            "error_type": "UnexpectedError",
            "message": str(e),
            "stack_trace": traceback.format_exc(),
            "content": content
        }

def is_partially_valid(yaml_content: str) -> bool:
    """Check if the YAML content is at least partially valid for analysis."""
    try:
        yaml.safe_load(yaml_content)
        return True
    except:
        # Try parsing line by line to see if any part is valid
        valid_lines = []
        for line in yaml_content.split('\n'):
            try:
                yaml.safe_load(line)
                valid_lines.append(line)
            except:
                continue
        return len(valid_lines) > 0

def analyze_yaml_structure(yaml_content: str, security_config: SecurityConfig = SecurityConfig()) -> Dict[str, Any]:
    """Enhanced YAML analysis with security checks."""
    try:
        # Perform security validation
        validate_yaml_security(yaml_content, security_config)
        
        # Parse YAML with safe_load
        data = yaml.safe_load(yaml_content)
        
        # Check nesting depth
        check_nesting_depth(data)
        
        # Perform memory usage check
        current_memory = sys.getsizeof(data)
        if current_memory > security_config.max_size:
            raise SecurityError(f"Parsed YAML exceeds memory limit of {security_config.max_size} bytes")
        
        # Continue with existing analysis
        analysis = {
            "isValid": True,
            "message": "YAML syntax is valid.",
            "details": {
                "structure": get_structure_info(data),
                "suggestions": get_best_practices(yaml_content),
                "statistics": get_yaml_statistics(yaml_content),
                "security_metrics": {
                    "size_bytes": len(yaml_content.encode('utf-8')),
                    "max_depth": check_nesting_depth(data),
                    "memory_usage": current_memory
                }
            }
        }
        return analysis
    except SecurityError as e:
        return {
            "isValid": False,
            "message": str(e),
            "error_type": "SecurityError",
            "suggestion": "Please review security constraints and adjust YAML content accordingly."
        }
    except yaml.YAMLError as e:
        error_details = parse_yaml_error(e)
        return {
            "isValid": False,
            "message": str(e),
            **error_details
        }
    
def is_duplicate_error(new_error: Dict[str, Any], existing_errors: List[Dict[str, Any]]) -> bool:
    """Check if an error is already present in the list of errors."""
    return any(
        err.get('line') == new_error.get('line') and
        err.get('error_type') == new_error.get('error_type') and
        err.get('message') == new_error.get('message')
        for err in existing_errors
    )