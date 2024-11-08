import json
import logging
import re
from azure.functions import HttpRequest, HttpResponse

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG)

def remove_markdown_notation(input_string):
    logging.debug("Starting markdown notation removal.")
    # Remove markdown notation, handle both triple backticks and variations like ~~~json
    cleaned_string = re.sub(r'```json\n|\n```', '', input_string)  # Remove both starting and trailing markdown notation for triple backticks
    cleaned_string = re.sub(r'~~~json\n|\n~~~', '', cleaned_string)  # Also remove any ~~~json annotations
    logging.debug("Completed markdown notation removal.")
    return cleaned_string.strip()  # Strip leading/trailing whitespace

def remove_nulls(d):
    logging.debug("Starting removal of null values.")
    if isinstance(d, dict):
        cleaned_dict = {k: remove_nulls(v) for k, v in d.items() if v is not None}
        logging.debug(f"Cleaned dictionary: {cleaned_dict}")
        return cleaned_dict
    elif isinstance(d, list):
        cleaned_list = [remove_nulls(i) for i in d if i is not None]
        logging.debug(f"Cleaned list: {cleaned_list}")
        return cleaned_list
    else:
        return d

def main(req: HttpRequest) -> HttpResponse:
    try:
        logging.debug("Received HTTP request.")
        
        # Get the raw input body as a byte string and decode it
        req_body = req.get_body().decode('utf-8')
        logging.debug(f"Original request body: {req_body}")

        # Remove markdown notation
        clean_json = remove_markdown_notation(req_body)
        logging.debug(f"Request body after removing markdown notation: {clean_json}")

        # Attempt to load the cleaned string as JSON to validate
        parsed_json = json.loads(clean_json)
        logging.debug(f"Parsed JSON: {parsed_json}")

        # Remove null values
        parsed_json = remove_nulls(parsed_json)
        logging.debug(f"JSON after null value removal: {parsed_json}")

        # Convert it back to a string for the response
        validated_json = json.dumps(parsed_json, indent=4)
        logging.debug(f"Final validated JSON string: {validated_json}")

        return HttpResponse(
            validated_json,
            status_code=200,
            mimetype="application/json"
        )

    except json.JSONDecodeError as e:
        logging.error(f"JSON decoding error: {e}")
        return HttpResponse(
            "Unable to clean and parse the provided input. Please ensure the input is structured as JSON.",
            status_code=400
        )

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return HttpResponse(
            f"An error occurred while processing the request: {e}",
            status_code=500
        )
