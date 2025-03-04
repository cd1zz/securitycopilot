import azure.functions as func
import logging
import json
import traceback
import yaml
import sys
import yamllint
from yamllint_config import get_yamllint_config
# Use absolute imports instead of relative
from config import MAX_YAML_SIZE, ALLOWED_TAGS
from security.validator import SecurityConfig, validate_yaml_security, SecurityError
from parsers.yaml_parser import parse_yaml, collect_yaml_errors
from errors.error_handler import get_detailed_error
from analysis.statistics import get_structure_info, get_yaml_statistics

# Define the app variable at the module level
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Make sure the decorator is at the module level and not inside a function or class
@app.route(route="yaml_validator", methods=["POST"])
def yaml_validator(req: func.HttpRequest) -> func.HttpResponse:
    """Main Azure Function handler for YAML validation."""
    logging.info('YAML validation function processing a request.')
    
    try:
        # Get YAML content
        yaml_content = req.get_body().decode('utf-8')
        
        # Check for empty content
        if not yaml_content.strip():
            return func.HttpResponse(
                json.dumps({
                    "isValid": False,
                    "details": {
                        "errors": [{
                            "error_type": "EmptyContent",
                            "message": "Empty YAML content provided",
                            "line": None,
                            "column": None
                        }],
                        "warnings": [],
                        "total_errors": 1,
                        "total_warnings": 0,
                        "structure": None,
                        "statistics": None
                    }
                }),
                mimetype="application/json"
            )
        
        # Get optional yamllint configuration from request
        try:
            req_body = req.get_json()
            custom_config = req_body.get('yamllint_config')
        except ValueError:
            custom_config = None
            
        # Create security config
        security_config = SecurityConfig(
            max_size=MAX_YAML_SIZE,
            allowed_tags=ALLOWED_TAGS
        )
        
        # Get all errors and warnings
        is_valid, result = parse_yaml(yaml_content, security_config, custom_config)
        
        if not is_valid:
            # Separate warnings from errors
            all_issues = result.get("all_errors", [])
            errors = [issue for issue in all_issues if issue.get("level") != "warning"]
            warnings = [issue for issue in all_issues if issue.get("level") == "warning"]
            
            error_result = {
                "isValid": len(errors) == 0,  # Only actual errors make it invalid
                "details": {
                    "errors": errors,
                    "warnings": warnings,  # Separate category for warnings
                    "total_errors": len(errors),
                    "total_warnings": len(warnings),
                    "structure": None,
                    "statistics": None
                }
            }
            return func.HttpResponse(
                json.dumps(error_result),
                mimetype="application/json"
            )
        
        # Return success with potential warnings
        success_result = {
            "isValid": True,
            "details": {
                "errors": [],
                "warnings": result.get("warnings", []),  # Include any warnings found
                "total_errors": 0,
                "total_warnings": len(result.get("warnings", [])),
                "structure": result.get("structure"),
                "statistics": result.get("statistics"),
                "suggestions": result.get("suggestions", [])
            }
        }
        return func.HttpResponse(
            json.dumps(success_result),
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.error(f"Unexpected error in yaml_validator: {str(e)}")
        logging.error(traceback.format_exc())
        return func.HttpResponse(
            json.dumps({
                "isValid": False,
                "details": {
                    "errors": [{
                        "error_type": "UnexpectedError",
                        "message": str(e),
                        "line": None,
                        "column": None
                    }],
                    "warnings": [],
                    "total_errors": 1,
                    "total_warnings": 0,
                    "structure": None,
                    "statistics": None
                }
            }),
            mimetype="application/json",
            status_code=500
        )

def create_error_response(error: Exception, context: dict = None) -> dict:
    """Create a standardized error response."""
    error_info = {
        "isValid": False,
        "message": str(error),
        "error_type": error.__class__.__name__,
        "stack_trace": traceback.format_exc()
    }
    
    if context:
        error_info["context"] = context
        
    return error_info

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
            "level": problem.level,  # "error" or "warning"
            "message": problem.message,
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

