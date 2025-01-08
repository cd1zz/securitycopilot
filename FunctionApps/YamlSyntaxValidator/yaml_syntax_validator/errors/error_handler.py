"""Error handling and formatting module for YAML validation."""

import yaml
from typing import Dict, Any, List
from ..security.validator import SecurityError

def parse_yaml_error(e: yaml.YAMLError) -> Dict[str, Any]:
    """Parse YAML error and provide detailed explanation and fix suggestions."""
    error_info = {
        "error_type": e.__class__.__name__,
        "line": None,
        "column": None,
        "problem_mark": None,
        "suggestion": None,
        "example_fix": None
    }

    if hasattr(e, 'problem_mark'):
        error_info.update({
            "line": e.problem_mark.line + 1,
            "column": e.problem_mark.column + 1,
            "problem_mark": f"Error at line {e.problem_mark.line + 1}, column {e.problem_mark.column + 1}"
        })

        # Extract context from the YAML content if available
        if hasattr(e.problem_mark, 'buffer'):
            yaml_lines = e.problem_mark.buffer.split('\n')
            context_start = max(0, e.problem_mark.line - 2)
            context_end = min(len(yaml_lines), e.problem_mark.line + 3)
            context = yaml_lines[context_start:context_end]
            
            pointer = ' ' * e.problem_mark.column + '^'
            context.insert(e.problem_mark.line - context_start + 1, pointer)
            
            error_info['context'] = {
                'lines': context,
                'start_line': context_start + 1,
                'problematic_line': e.problem_mark.line + 1
            }

    # Add detailed error analysis and suggestions
    error_msg = str(e).lower()
    if "mapping values are not allowed here" in error_msg:
        error_info.update({
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
        })
    elif "found character '\\t'" in error_msg:
        error_info.update({
            "suggestion": "Replace tabs with spaces. YAML does not allow tabs for indentation.",
            "example_fix": """
# Replace:
key1:
→nested_key: value  # Tab character

# With:
key1:
  nested_key: value  # Spaces"""
        })
    elif "found unexpected ':'" in error_msg:
        error_info.update({
            "suggestion": "Make sure colons in values are properly quoted.",
            "example_fix": """
# Instead of:
message: Hello: World  # Unquoted colon

# Use:
message: 'Hello: World'  # Quoted value with colon"""
        })
    else:
        error_info["suggestion"] = get_yaml_suggestion(str(e))

    return error_info

def get_yaml_suggestion(error_msg: str) -> str:
    """Generate helpful suggestions based on common YAML errors."""
    suggestions = {
        "mapping values are not allowed here": 
            "Check your indentation. Make sure each nested item is properly indented with spaces.",
        "expected '<document start>'": 
            "Your YAML might be malformed. Ensure there are no tabs and all colons are followed by spaces.",
        "found character '\\t'":
            "Replace all tabs with spaces. YAML does not allow tabs for indentation.",
        "found unexpected ':'":
            "Make sure colons are followed by a space and the value is on the same line or properly indented below.",
        "found undefined alias":
            "Check that all YAML anchors (&) have corresponding aliases (*).",
    }
    
    for error_pattern, suggestion in suggestions.items():
        if error_pattern.lower() in error_msg.lower():
            return suggestion
    
    return "Check your YAML syntax, particularly indentation and key-value formatting."

def get_detailed_error(e: Exception, yaml_content: str) -> Dict[str, Any]:
    """Generate detailed, human-readable error information."""
    error_info = {
        "message": "",
        "line": None,
        "column": None,
        "context": [],
        "error_type": e.__class__.__name__
    }

    try:
        if isinstance(e, yaml.YAMLError):
            if hasattr(e, 'problem_mark'):
                mark = e.problem_mark
                line_num = mark.line + 1
                col_num = mark.column + 1
                error_info.update({
                    "line": line_num,
                    "column": col_num
                })

                # Get context lines
                lines = yaml_content.split('\n')
                start_line = max(0, line_num - 3)
                end_line = min(len(lines), line_num + 2)
                
                # Add line numbers and content
                context_lines = []
                for i in range(start_line, end_line):
                    line_indicator = '-> ' if i + 1 == line_num else '   '
                    context_lines.append(f"{line_indicator}{i + 1}: {lines[i]}")
                    if i + 1 == line_num:
                        # Add pointer to the specific column
                        context_lines.append('   ' + ' ' * (len(str(i + 1)) + 2 + col_num) + '^')

                error_info['context'] = context_lines
                
                # Add the specific problematic line and surrounding context
                error_info['code_context'] = {
                    'lines': lines[start_line:end_line],
                    'start_line': start_line + 1,
                    'problematic_line': line_num,
                    'problematic_column': col_num
                }

            error_info["message"] = get_human_readable_error(str(e))

        elif isinstance(e, SecurityError):
            error_info["message"] = str(e)
        else:
            error_info["message"] = f"Unexpected error: {str(e)}"

    except Exception as nested_error:
        error_info["message"] = f"Error while processing YAML: {str(e)}"
        error_info["processing_error"] = str(nested_error)

    return error_info

def get_human_readable_error(error_msg: str) -> str:
    """Convert YAML error messages into human-readable explanations."""
    if "mapping values are not allowed here" in error_msg.lower():
        return "There appears to be an indentation error. Check that all nested items are properly indented with spaces (not tabs)."
    elif "found character '\\t'" in error_msg.lower():
        return "The YAML contains tab characters. Please replace all tabs with spaces."
    elif "found unexpected ':'" in error_msg.lower():
        return "Found an unexpected colon (:). If you're using colons in values, they need to be quoted."
    elif "expected <block end>" in error_msg.lower():
        return "There's an issue with block structure. This usually means incorrect indentation or missing line breaks."
    elif "found undefined alias" in error_msg.lower():
        return "Found a YAML alias (*) without a corresponding anchor (&)."
    else:
        return f"YAML Parsing Error: {error_msg}"