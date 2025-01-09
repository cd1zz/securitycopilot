"""Main Azure Function handler for YAML validation."""

import logging
import azure.functions as func
import json
import traceback
import sys
from .security.validator import SecurityConfig, validate_yaml_security, SecurityError
from .parsers.yaml_parser import parse_yaml, collect_yaml_errors
import yaml
from .errors.error_handler import get_detailed_error
from .analysis.statistics import get_structure_info, get_yaml_statistics
from .config import MAX_YAML_SIZE, ALLOWED_TAGS

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

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        yaml_content = req.get_body().decode('utf-8')
        security_config = SecurityConfig(
            max_size=MAX_YAML_SIZE,
            allowed_tags=ALLOWED_TAGS
        )
        
        # Get all errors (syntax, security, etc.)
        is_valid, result = parse_yaml(yaml_content, security_config)
        
        if not is_valid:
            return func.HttpResponse(
                json.dumps({
                    "isValid": False,
                    "details": {
                        "errors": result.get("all_errors", []),
                        "total_errors": len(result.get("all_errors", [])),
                        "structure": None,
                        "statistics": None
                    }
                }),
                mimetype="application/json"
            )
        
        # Collect all errors
        errors = collect_yaml_errors(yaml_content)
        
        if errors:
            return func.HttpResponse(
                json.dumps({
                    "isValid": False,
                    "details": {
                        "errors": errors,
                        "total_errors": len(errors),
                        "structure": None,
                        "statistics": None
                    }
                }),
                mimetype="application/json"
            )
        
        # If no errors, parse and return success
        data = yaml.safe_load(yaml_content)
        return func.HttpResponse(
            json.dumps({
                "isValid": True,
                "details": {
                    "errors": [],
                    "total_errors": 0,
                    "structure": get_structure_info(data),
                    "statistics": get_yaml_statistics(yaml_content)
                }
            }),
            mimetype="application/json"
        )
        
    except Exception as e:
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
                    "total_errors": 1,
                    "structure": None,
                    "statistics": None
                }
            }),
            mimetype="application/json",
            status_code=500  # Keep 500 for actual server errors
        )