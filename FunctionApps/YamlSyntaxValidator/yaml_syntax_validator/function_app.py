import azure.functions as func
import logging
import json
import traceback
import yaml
import sys
# Use absolute imports instead of relative
from config import MAX_YAML_SIZE, ALLOWED_TAGS
from security.validator import SecurityConfig, validate_yaml_security, SecurityError
from parsers.yaml_parser import parse_yaml, collect_yaml_errors
from errors.error_handler import get_detailed_error
from analysis.statistics import get_structure_info, get_yaml_statistics

# Define the app variable at the module level
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

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

# Make sure the decorator is at the module level and not inside a function or class
@app.route(route="yaml_validator", methods=["POST"])
def yaml_validator(req: func.HttpRequest) -> func.HttpResponse:
    """Main Azure Function handler for YAML validation."""
    logging.info('YAML validation function processing a request.')
    
    try:
        yaml_content = req.get_body().decode('utf-8')
        
        # Add logging for content
        logging.info(f"Content length: {len(yaml_content)}")
        if len(yaml_content) > 0:
            logging.info(f"Content preview (first 100 chars): {yaml_content[:100]}")
        else:
            logging.warning("Received empty content")
        
        security_config = SecurityConfig(
            max_size=MAX_YAML_SIZE,
            allowed_tags=ALLOWED_TAGS
        )
        
        # Add security config logging
        logging.info(f"Security config max size: {security_config.max_size}")
        logging.info(f"Security config allowed tags: {security_config.allowed_tags}")
        
        # Get all errors (syntax, security, etc.)
        logging.info("Calling parse_yaml function")
        is_valid, result = parse_yaml(yaml_content, security_config)
        
        # Log validation result
        logging.info(f"Validation result: is_valid={is_valid}")
        if result:
            logging.info(f"Result keys: {list(result.keys())}")
        
        if not is_valid:
            error_result = {
                "isValid": False,
                "details": {
                    "errors": result.get("all_errors", []),
                    "total_errors": len(result.get("all_errors", [])),
                    "structure": None,
                    "statistics": None
                }
            }
            logging.info(f"Returning invalid response: {json.dumps(error_result)[:200]}")
            return func.HttpResponse(
                json.dumps(error_result),
                mimetype="application/json"
            )
        
        # Collect all errors
        logging.info("Collecting all YAML errors")
        errors = collect_yaml_errors(yaml_content)
        
        if errors:
            error_result = {
                "isValid": False,
                "details": {
                    "errors": errors,
                    "total_errors": len(errors),
                    "structure": None,
                    "statistics": None
                }
            }
            logging.info(f"Returning error response with {len(errors)} errors")
            return func.HttpResponse(
                json.dumps(error_result),
                mimetype="application/json"
            )
        
        # If no errors, parse and return success
        logging.info("No errors found, parsing YAML")
        try:
            data = yaml.safe_load(yaml_content)
            
            if data is None:
                logging.warning("YAML parsed to None")
                error_result = {
                    "isValid": False,
                    "details": {
                        "errors": [{
                            "error_type": "EmptyContent",
                            "message": "YAML content is empty or only contains comments",
                            "line": None,
                            "column": None
                        }],
                        "total_errors": 1,
                        "structure": None,
                        "statistics": None
                    }
                }
                return func.HttpResponse(
                    json.dumps(error_result),
                    mimetype="application/json"
                )
            
            structure_info = get_structure_info(data)
            stats = get_yaml_statistics(yaml_content)
            
            success_result = {
                "isValid": True,
                "details": {
                    "errors": [],
                    "total_errors": 0,
                    "structure": structure_info,
                    "statistics": stats
                }
            }
            logging.info("Returning success response")
            return func.HttpResponse(
                json.dumps(success_result),
                mimetype="application/json"
            )
        except Exception as yaml_parse_error:
            logging.error(f"Error during final YAML parsing: {str(yaml_parse_error)}")
            return func.HttpResponse(
                json.dumps({
                    "isValid": False,
                    "details": {
                        "errors": [{
                            "error_type": "ParseError",
                            "message": str(yaml_parse_error),
                            "line": None,
                            "column": None
                        }],
                        "total_errors": 1,
                        "structure": None,
                        "statistics": None
                    }
                }),
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
                    "total_errors": 1,
                    "structure": None,
                    "statistics": None
                }
            }),
            mimetype="application/json",
            status_code=500  # Keep 500 for actual server errors
        )