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

def replace_nulls_with_none(d):
    logging.debug("Starting replacement of null values with 'None'.")
    if isinstance(d, dict):
        replaced_dict = {k: replace_nulls_with_none(v) for k, v in d.items()}
        logging.debug(f"Replaced dictionary: {replaced_dict}")
        return replaced_dict
    elif isinstance(d, list):
        replaced_list = [replace_nulls_with_none(i) for i in d]
        logging.debug(f"Replaced list: {replaced_list}")
        return replaced_list
    elif d is None:
        return "None"  # Replace null with the string "None"
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

        # Replace null values with the string "None"
        parsed_json = replace_nulls_with_none(parsed_json)
        logging.debug(f"JSON after replacing null values with 'None': {parsed_json}")

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
