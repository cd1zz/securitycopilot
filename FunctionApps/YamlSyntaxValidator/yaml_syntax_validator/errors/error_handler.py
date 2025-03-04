"""Error handling and formatting module for YAML validation."""

import yaml
from typing import Dict, Any, List, Tuple
from security.validator import SecurityError

# Registry of known YAML error patterns and their human-readable details
ERROR_PATTERNS = {
    "mapping values are not allowed here": {
        "error_type": "IndentationError",
        "message": "There might be an indentation error. Check that all nested items are properly indented with spaces (not tabs). Also check for more than one ':' on the same line.",
        "suggestion": "Indentation error detected. The line is not properly indented relative to its parent element.",
        "error_details": {
            "problem": "Incorrect indentation level",
            "explanation": "In YAML, nested elements must be indented with 2 spaces relative to their parent element",
            "common_causes": [
                "Using tabs instead of spaces",
                "Inconsistent indentation levels",
                "Missing parent element"
            ]
        },
        "example_fix": """
# Correct indentation:
parent_key:
  child_key1: value    # Indented with 2 spaces
  child_key2:          # Same level as child_key1
    grandchild: value  # Indented with 2 more spaces"""
    },
    "found character '\\t'": {
        "error_type": "IndentationError",
        "message": "The YAML contains tab characters. Please replace all tabs with spaces.",
        "suggestion": "Replace tabs with spaces. YAML does not allow tabs for indentation.",
        "example_fix": """
# Replace:
key1:
→nested_key: value  # Tab character

# With:
key1:
  nested_key: value  # Spaces"""
    },
    "found unexpected ':'": {
        "error_type": "SyntaxError",
        "message": "Found an unexpected colon (:). If you're using colons in values, they need to be quoted.",
        "suggestion": "Make sure colons in values are properly quoted.",
        "example_fix": """
# Instead of:
message: Hello: World  # Unquoted colon

# Use:
message: 'Hello: World'  # Quoted value with colon"""
    },
    "expected <block end>": {
        "error_type": "StructureError",
        "message": "There's an issue with block structure. This usually means incorrect indentation or missing line breaks.",
        "suggestion": "Check the lines above and below for proper indentation.",
        "example_fix": """
# Instead of:
key1: value1 key2: value2  # Missing line break

# Use:
key1: value1
key2: value2"""
    },
    "found undefined alias": {
        "error_type": "AliasError",
        "message": "Found a YAML alias (*) without a corresponding anchor (&).",
        "suggestion": "Check that all YAML anchors (&) have corresponding aliases (*).",
        "example_fix": """
# Correct usage:
defaults: &defaults
  timeout: 30
  retry: 3

production:
  <<: *defaults  # Using the alias"""
    }
}

def get_error_context(lines: List[str], error_line: int, context_lines: int = 2) -> Tuple[List[str], int, int]:
    """
    Get context lines around an error with configurable window size.
    
    Args:
        lines: List of all lines in the YAML content
        error_line: The line number where the error occurred (0-based)
        context_lines: Number of lines to include before and after error
    
    Returns:
        Tuple containing the context lines, start line number, and end line number
    """
    start_line = max(0, error_line - context_lines)
    end_line = min(len(lines), error_line + context_lines + 1)
    return lines[start_line:end_line], start_line, end_line

def format_context_lines(lines: List[str], error_line: int, error_column: int, start_line: int, level: str = "error") -> List[str]:
    """
    Format context lines with consistent line numbers and error indicators.
    
    Args:
        lines: The context lines to format
        error_line: The line number where the error occurred (1-based)
        error_column: The column number where the error occurred (1-based)
        start_line: The starting line number of the context (0-based)
        level: The level of the issue ("error" or "warning")
    
    Returns:
        List of formatted context lines with error indicators
    """
    formatted_lines = []
    prefix = "-> " if level == "error" else "~> "  # Different prefix for warnings
    
    for i, line in enumerate(lines):
        current_line = start_line + i + 1
        indicator = prefix if current_line == error_line else '   '
        formatted_lines.append(f"{indicator}{current_line}: {line}")
        if current_line == error_line:
            # Add pointer to the specific column
            formatted_lines.append('   ' + ' ' * (len(str(current_line)) + 2 + error_column) + '^')
    return formatted_lines

def get_error_type(error: Exception) -> str:
    """
    Determine the specific type of YAML error.
    
    Args:
        error: The exception to analyze
        
    Returns:
        String indicating the error type
    """
    if isinstance(error, yaml.YAMLError):
        error_msg = str(error).lower()
        for pattern, details in ERROR_PATTERNS.items():
            if pattern in error_msg:
                return details["error_type"]
    return error.__class__.__name__

def get_human_readable_error(error_msg: str, line_content: str = None) -> str:
    """More context-aware error message generation."""
    error_msg_lower = error_msg.lower()
    
    # If we have line content, do more specific analysis
    if line_content and "mapping values are not allowed here" in error_msg_lower:
        # Check if there's an unquoted colon in a value
        if ':' in line_content:
            key_value = line_content.split(':', 1)
            if len(key_value) > 1 and ':' in key_value[1].strip():
                return "Found an unquoted colon in the value. Values containing colons must be quoted."
                
    # Fall back to existing patterns
    for pattern, details in ERROR_PATTERNS.items():
        if pattern in error_msg_lower:
            return details["message"]
            
    return f"YAML Parsing Error: {error_msg}"

def get_error_suggestion(error_msg: str) -> str:
    """
    Generate helpful suggestions based on common YAML errors.
    
    Args:
        error_msg: The original error message
        
    Returns:
        A suggestion for fixing the error
    """
    error_msg_lower = error_msg.lower()
    for pattern, details in ERROR_PATTERNS.items():
        if pattern in error_msg_lower:
            return details["suggestion"]
    return "Check your YAML syntax, particularly indentation and key-value formatting."

def parse_yaml_error(e: yaml.YAMLError) -> Dict[str, Any]:
    """
    Parse YAML error and provide detailed explanation and fix suggestions.
    
    Args:
        e: The YAML error to parse
        
    Returns:
        Dictionary containing detailed error information
    """
    error_info = {
        "error_type": get_error_type(e),
        "line": None,
        "column": None,
        "problem_mark": None,
        "suggestion": get_error_suggestion(str(e)),
        "example_fix": None,
        "level": "error"  # YAML errors from parser are always errors
    }

    if not hasattr(e, 'problem_mark'):
        return error_info

    mark = e.problem_mark
    error_info.update({
        "line": mark.line + 1,
        "column": mark.column + 1,
        "problem_mark": f"Error at line {mark.line + 1}, column {mark.column + 1}"
    })

    if hasattr(mark, 'buffer'):
        yaml_lines = mark.buffer.split('\n')
        context_lines, start_line, _ = get_error_context(yaml_lines, mark.line)
        
        error_info['context'] = {
            'lines': context_lines,
            'start_line': start_line + 1,
            'problematic_line': mark.line + 1
        }

        # Add example fix if available
        error_msg = str(e).lower()
        for pattern, details in ERROR_PATTERNS.items():
            if pattern in error_msg:
                error_info["example_fix"] = details.get("example_fix")
                error_info["error_details"] = details.get("error_details")
                break

    return error_info

def get_detailed_error(e: Exception, yaml_content: str) -> Dict[str, Any]:
    """
    Generate detailed, human-readable error information.
    
    Args:
        e: The exception to analyze
        yaml_content: The full YAML content being parsed
        
    Returns:
        Dictionary containing detailed error information with context
    """
    error_info = {
        "message": "",
        "line": None,
        "column": None,
        "context": [],
        "error_type": get_error_type(e),
        "level": "error"  # Default to error for exceptions
    }

    try:
        if not isinstance(e, yaml.YAMLError) or not hasattr(e, 'problem_mark'):
            error_info["message"] = str(e)
            return error_info

        mark = e.problem_mark
        line_num = mark.line + 1
        col_num = mark.column + 1
        
        lines = yaml_content.split('\n')
        context_lines, start_line, _ = get_error_context(lines, line_num - 1)
        
        error_info.update({
            "line": line_num,
            "column": col_num,
            "message": get_human_readable_error(str(e)),
            "context": format_context_lines(context_lines, line_num, col_num, start_line, level=error_info.get("level", "error")),
            "code_context": {
                'lines': context_lines,
                'start_line': start_line + 1,
                'problematic_line': line_num,
                'problematic_column': col_num
            }
        })

    except Exception as nested_error:
        error_info.update({
            "message": f"Error while processing YAML: {str(e)}",
            "processing_error": str(nested_error)
        })

    return error_info

def convert_yamllint_problems(problems, yaml_content):
    """
    Convert yamllint problems to our error format.
    
    Args:
        problems: YAMLlint problem objects
        yaml_content: The original YAML content
        
    Returns:
        List of formatted error/warning objects
    """
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
            "level": problem.level,  # "error" or "warning"
            "rule": problem.rule,    # The yamllint rule that was violated
            "message": problem.desc, # The description from yamllint
            "code_context": {
                'lines': context_lines,
                'start_line': start_line + 1,
                'problematic_line': problem.line,
                'problematic_column': problem.column + 1
            },
            "context": format_context_lines(
                context_lines, 
                problem.line, 
                problem.column + 1, 
                start_line, 
                level=problem.level
            )
        }
        errors.append(error_details)
    
    return errors