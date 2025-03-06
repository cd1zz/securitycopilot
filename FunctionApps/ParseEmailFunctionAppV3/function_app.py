import logging
import azure.functions as func
import json
import base64
from parsers.email_parser import parse_email

logging.getLogger().setLevel(logging.DEBUG)
logger = logging.getLogger("AzureFunction")
logger.setLevel(logging.DEBUG)

# Initialize the function app
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="", methods=["POST"])
def parse_email_functionapp(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function endpoint to parse phishing emails.
    
    Args:
        req (func.HttpRequest): HTTP request object
        
    Returns:
        func.HttpResponse: HTTP response with parsed email data in JSON format
    """
    logging.info("Phishing Parser function processed a request.")
    
    try:
        # Get email content from the request
        email_content = req.get_body()
        
        if not email_content:
            # Check if email content is provided as a base64 string in JSON
            try:
                req_body = req.get_json()
                if "email_content_base64" in req_body:
                    email_content = base64.b64decode(req_body["email_content_base64"])
                elif "email_content" in req_body:
                    email_content = req_body["email_content"].encode('utf-8')
            except ValueError:
                pass
        
        if not email_content:
            return func.HttpResponse(
                json.dumps({"error": "No email content provided"}),
                mimetype="application/json",
                status_code=400
            )
        
        # Get max depth parameter (default to 10)
        max_depth = 10
        try:
            params = req.params
            if "max_depth" in params:
                max_depth = int(params["max_depth"])
        except (ValueError, TypeError):
            pass
        
        # Parse the email
        parsed_data = parse_email(email_content, max_depth=max_depth)
        
        # Return the parsed data as JSON
        return func.HttpResponse(
            json.dumps(parsed_data, indent=2, default=str),
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Failed to process email: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )
