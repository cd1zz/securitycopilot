"""YAML parsing module with failsafe error handling and yamllint integration."""
import re
import yaml
import sys
import traceback
import logging
import yamllint
from yamllint.config import YamlLintConfig
from typing import Dict, Any, Tuple, List
from security.validator import SecurityConfig, SecurityError, validate_yaml_security, check_nesting_depth
from analysis.statistics import get_structure_info, get_best_practices, get_yaml_statistics
from errors.error_handler import parse_yaml_error, get_detailed_error
from yamllint_config import get_yamllint_config



def run_yamllint_validation(content: str, yamllint_config: YamlLintConfig = None) -> List[Dict[str, Any]]:
    """
    Run yamllint on content with optional custom configuration.
    
    Args:
        content: YAML content to validate
        yamllint_config: Optional yamllint configuration
        
    Returns:
        List of formatted errors
    """
    try:
        # Use default config if none provided
        if not yamllint_config:
            yamllint_config = get_yamllint_config()
            
        problems = yamllint.linter.run(content, yamllint_config)
        
        # Convert to our format
        errors = []
        content_lines = content.split('\n')
        
        for problem in problems:
            line_num = problem.line
            col_num = problem.column + 1  # yamllint uses 0-based columns
            
            # Get context
            start_line = max(0, line_num - 3)
            end_line = min(len(content_lines), line_num + 2)
            context_lines = content_lines[start_line:end_line]
            
            formatted_context = []
            for i, line in enumerate(context_lines):
                curr_line = start_line + i + 1
                prefix = "-> " if curr_line == line_num else "   "
                formatted_context.append(f"{prefix}{curr_line}: {line}")
                if curr_line == line_num:
                    # Add pointer to column
                    formatted_context.append(' ' * (len(str(curr_line)) + 4 + col_num) + '^')
                    
            error_detail = {
                "line": line_num,
                "column": col_num,
                "error_type": "YAMLLintError",
                "level": problem.level,  # 'error' or 'warning'
                "rule": problem.rule,    # yamllint rule that was violated
                "message": problem.desc, # The description from yamllint
                "context": formatted_context,
                "code_context": {
                    "lines": context_lines,
                    "start_line": start_line + 1,
                    "problematic_line": line_num,
                    "problematic_column": col_num
                }
            }
            errors.append(error_detail)
            
        return errors
    except Exception as e:
        logging.error(f"Error running yamllint: {str(e)}")
        return [{
            "error_type": "YAMLLintError",
            "message": f"Error running yamllint: {str(e)}",
            "line": None,
            "column": None
        }]
def convert_yamllint_problems(problems, yaml_content):
    """Convert yamllint problems to our error format."""
    errors = []
    lines = yaml_content.split('\n')
    
    for problem in problems:
        # Get context lines for the error
        line_index = problem.line - 1
        start_line = max(0, line_index - 2)
        end_line = min(len(lines), line_index + 3)
        context_lines = lines[start_line:end_line]
        
        error_details = {
            "line": problem.line,
            "column": problem.column + 1,  # Convert 0-based to 1-based for consistency
            "error_type": "YAMLLintError",
            "level": problem.level,  # Preserve "error" or "warning"
            "message": problem.desc,
            "rule": problem.rule,  # Add the rule that was violated
            "code_context": {
                'lines': context_lines,
                'start_line': start_line + 1,
                'problematic_line': problem.line,
                'problematic_column': problem.column + 1
            },
            "context": [
                f"   {i+start_line+1}: {line}" if i+start_line+1 != problem.line else f"-> {i+start_line+1}: {line}"
                for i, line in enumerate(context_lines)
            ]
        }
        errors.append(error_details)
    
    return errors

def collect_yaml_errors(content: str, yamllint_config: YamlLintConfig = None) -> List[Dict[str, Any]]:
    """Collect all YAML errors in the content using yamllint and additional checks."""
    errors = []
    
    # First run yamllint
    yamllint_errors = run_yamllint_validation(content, yamllint_config)
    
    # Apply filtering to yamllint errors
    filtered_yamllint_errors = [
        error for error in yamllint_errors
        if not should_filter_error(error)
    ]
    
    errors.extend(filtered_yamllint_errors)
    
    # Additional validation for checks not covered by yamllint
    lines = content.split('\n')
    
    # Check for specific security patterns not covered by yamllint
    for i, line in enumerate(lines):
        # Check for potentially dangerous YAML tags
        if "!!python/" in line:
            error_details = {
                "line": i + 1,
                "column": line.find("!!python/") + 1,
                "error_type": "SecurityError",
                "level": "error",
                "message": "Potentially dangerous Python tag detected. This could lead to code execution vulnerabilities.",
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
                    "problematic_column": line.find("!!python/") + 1
                }
            }
            errors.append(error_details)
    
    return errors

def parse_yaml(content: str, security_config: SecurityConfig, custom_yamllint_config: Dict[str, Any] = None) -> Tuple[bool, Dict[str, Any]]:
    """Parse YAML content with comprehensive error handling and yamllint integration."""
    logging.info("Starting parse_yaml function")
    
    # Initialize parsed_data as None - we'll cache it when successfully parsed
    parsed_data = None
    
    try:
        # Security validation
        try:
            logging.info("Attempting security validation")
            # First do string-based checks before parsing
            content_size = len(content.encode('utf-8'))
            if content_size > security_config.max_size:
                raise SecurityError(f"YAML content exceeds maximum size of {security_config.max_size} bytes")
            
            # Quick string-based dangerous tag check
            for dangerous_tag in ["!!python/object", "!!python/module"]:
                if dangerous_tag in content:
                    raise SecurityError(f"Potentially dangerous YAML tag '{dangerous_tag}' detected")
            
            # Only parse once for memory checks if needed
            if parsed_data is None:
                try:
                    parsed_data = yaml.safe_load(content)
                except yaml.YAMLError:
                    # We'll catch this later in the full parsing step
                    pass
                
            # Complete the security validation
            validate_yaml_security(content, security_config, parsed_data)
            logging.info("Security validation passed successfully")
        except SecurityError as se:
            logging.error(f"Security validation failed: {str(se)}")
            return False, {
                "error": se,
                "error_type": "SecurityError",
                "message": str(se),
                "all_errors": [{
                    "error_type": "SecurityError",
                    "message": str(se),
                    "line": None,
                    "column": None,
                    "level": "error"  # Security issues are always errors
                }],
                "content": content
            }
        
        # Collect all issues using yamllint and additional checks
        logging.info("Collecting errors with yamllint and additional checks")
        yamllint_config = get_yamllint_config(custom_yamllint_config)
        all_issues = collect_yaml_errors(content, yamllint_config)
        
        # Separate errors from warnings
        errors = [issue for issue in all_issues if issue.get("level") != "warning"]
        warnings = [issue for issue in all_issues if issue.get("level") == "warning"]
        
        if errors:
            logging.info(f"Found {len(errors)} errors and {len(warnings)} warnings")
            return False, {
                "error": "YAML errors found",
                "error_type": "YAMLError",
                "all_errors": all_issues,  # Keep all issues for reference
                "errors": errors,          # Just the actual errors
                "warnings": warnings,      # Just the warnings
                "error_count": len(errors),
                "warning_count": len(warnings),
                "content": content
            }
        logging.info(f"No errors found, {len(warnings)} warnings")

        # If no errors and we haven't parsed the YAML yet, do it now
        try:
            if parsed_data is None:
                logging.info("Attempting full YAML parsing")
                parsed_data = yaml.safe_load(content)
            
            # Handle None result
            if parsed_data is None:
                logging.warning("YAML content parsed to None")
                return False, {
                    "error": ValueError("Empty YAML content"),
                    "error_type": "EmptyContent",
                    "message": "YAML content is empty or only contains comments",
                    "all_errors": [{
                        "error_type": "EmptyContent",
                        "message": "YAML content is empty or only contains comments",
                        "line": None,
                        "column": None,
                        "level": "error"
                    }],
                    "content": content
                }
                
            # Depth check
            try:
                logging.info("Checking nesting depth")
                check_nesting_depth(parsed_data)
                logging.info("Nesting depth check passed")
            except SecurityError as de:
                logging.error(f"Depth check failed: {str(de)}")
                return False, {
                    "error": de,
                    "error_type": "DepthError",
                    "message": str(de),
                    "all_errors": [{
                        "error_type": "DepthError",
                        "message": str(de),
                        "line": None,
                        "column": None,
                        "level": "error"
                    }],
                    "content": content
                }
            
            # Memory usage check (if not already done in security validation)
            logging.info("Checking memory usage")
            current_memory = sys.getsizeof(parsed_data)
            logging.info(f"Current memory usage: {current_memory} bytes")
            if current_memory > security_config.max_size:
                logging.error(f"Memory usage exceeded: {current_memory} > {security_config.max_size}")
                return False, {
                    "error": SecurityError(f"Parsed YAML exceeds memory limit of {security_config.max_size} bytes"),
                    "error_type": "MemoryError",
                    "message": f"Memory usage ({current_memory} bytes) exceeds limit ({security_config.max_size} bytes)",
                    "all_errors": [{
                        "error_type": "MemoryError",
                        "message": f"Memory usage ({current_memory} bytes) exceeds limit ({security_config.max_size} bytes)",
                        "line": None,
                        "column": None,
                        "level": "error"
                    }],
                    "content": content
                }
            
            # If we get here, the YAML is valid (but might have warnings)
            logging.info("YAML validation successful")
            structure_info = get_structure_info(parsed_data)
            logging.info(f"Generated structure info with {len(structure_info)} elements")
            
            best_practices = get_best_practices(content)
            logging.info(f"Generated {len(best_practices)} best practice suggestions")
            
            statistics = get_yaml_statistics(content)
            logging.info(f"Generated statistics: {statistics}")
            
            return True, {
                "data": parsed_data,
                "structure": structure_info,
                "suggestions": best_practices,
                "statistics": statistics,
                "warnings": warnings,  # Include any warnings even for valid YAML
                "content": content,
                "message": "YAML validation successful" if not warnings else "YAML validation successful with warnings"
            }
            
        except yaml.YAMLError as ye:
            logging.error(f"YAML parsing error: {str(ye)}")
            error_details = get_detailed_error(ye, content)
            error_details["level"] = "error"  # YAML syntax errors are always errors
            return False, {
                "error": ye,
                "error_type": "YAMLError",
                "error_details": error_details,
                "message": str(ye),
                "all_errors": [error_details],
                "content": content
            }
            
    except Exception as e:
        logging.error(f"Unexpected error in parse_yaml: {str(e)}")
        logging.error(traceback.format_exc())
        return False, {
            "error": e,
            "error_type": "UnexpectedError",
            "message": str(e),
            "all_errors": [{
                "error_type": "UnexpectedError",
                "message": str(e),
                "line": None,
                "column": None,
                "level": "error"
            }],
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

def analyze_yaml_structure(yaml_content: str, security_config: SecurityConfig = None, custom_yamllint_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """Enhanced YAML analysis with security checks and yamllint integration."""
    if security_config is None:
        from config import MAX_YAML_SIZE, MAX_NESTING_DEPTH, ALLOWED_TAGS
        security_config = SecurityConfig(
            max_size=MAX_YAML_SIZE,
            allowed_tags=ALLOWED_TAGS
        )
        
    try:
        # Perform security validation
        validate_yaml_security(yaml_content, security_config)
        
        # Run yamllint validation
        yamllint_config = get_yamllint_config(custom_yamllint_config)
        yamllint_errors = run_yamllint_validation(yaml_content, yamllint_config)
        
        if yamllint_errors:
            return {
                "isValid": False,
                "message": "YAML linting errors found",
                "errors": yamllint_errors,
                "total_errors": len(yamllint_errors)
            }
        
        # Parse YAML with safe_load
        data = yaml.safe_load(yaml_content)
        
        # Additional checks
        check_nesting_depth(data)
        current_memory = sys.getsizeof(data)
        if current_memory > security_config.max_size:
            raise SecurityError(f"Parsed YAML exceeds memory limit of {security_config.max_size} bytes")
        
        # Generate analysis
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
    
def should_filter_error(error: Dict[str, Any]) -> bool:
    """
    Determine if an error should be filtered out from the results.
    
    Args:
        error: The error dictionary to check
        
    Returns:
        Boolean indicating if the error should be filtered (True = filter out)
    """
    # Option to completely ignore certain warnings
    ignored_rules = []  # Add any rules you want to completely ignore
    
    if (error.get("error_type") == "YAMLLintError" and 
        error.get("level") == "warning" and
        error.get("rule") in ignored_rules):
        return True
        
    return False

def is_duplicate_error(new_error: Dict[str, Any], existing_errors: List[Dict[str, Any]]) -> bool:
    """
    Check if an error is already present or overlaps with existing errors.
    
    Args:
        new_error: The error to check for duplication
        existing_errors: List of existing errors
        
    Returns:
        Boolean indicating if this is a duplicate
    """
    # Check for exact matches
    exact_match = any(
        err.get('line') == new_error.get('line') and
        err.get('error_type') == new_error.get('error_type') and
        err.get('message') == new_error.get('message')
        for err in existing_errors
    )
    
    if exact_match:
        return True
    
    # Check for semantic duplicates (same line, similar message)
    line_num = new_error.get('line')
    error_type = new_error.get('error_type')
    message = new_error.get('message', '').lower()
    
    if line_num is not None:
        # Look for errors on the same line
        for err in existing_errors:
            if err.get('line') == line_num:
                # Same line errors
                existing_message = err.get('message', '').lower()
                existing_type = err.get('error_type')
                
                # Check if messages are similar
                if (message and existing_message and 
                    (message in existing_message or existing_message in message)):
                    return True
                
                # Some error types overlap in meaning (e.g., IndentationError and yamllint indentation rule)
                if (error_type == "YAMLLintError" and err.get('rule') == "indentation" and
                    existing_type in ["IndentationError", "SyntaxError"]):
                    return True
                
                # Overlapping error types
                overlapping_types = [
                    ("YAMLLintError", "SyntaxError"),
                    ("EmptyContent", "YAMLError"),
                    ("IndentationError", "SyntaxError")
                ]
                
                if any(
                    (error_type == pair[0] and existing_type == pair[1]) or
                    (error_type == pair[1] and existing_type == pair[0])
                    for pair in overlapping_types
                ):
                    return True
    
    return False