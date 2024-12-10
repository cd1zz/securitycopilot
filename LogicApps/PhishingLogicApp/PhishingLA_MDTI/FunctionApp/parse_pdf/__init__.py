import base64
import re
from pdfminer.high_level import extract_text
from io import BytesIO
import logging
import json
import azure.functions as func
import traceback

# Azure Function entry point
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing request to extract text from base64 encoded PDF string.")

    try:
        # Get the request body as raw bytes
        raw_body = req.get_body()
        logging.debug(f"Raw request body (as bytes): {raw_body[:100]}...")  # Log first 100 characters for safety

        # Attempt to parse as JSON (if applicable) or assume it's the base64 string directly
        try:
            req_body = json.loads(raw_body.decode('utf-8'))
            logging.debug(f"Extracted request JSON body successfully: {req_body}")

            # Additional check to confirm req_body is a dictionary
            if not isinstance(req_body, dict):
                logging.warning(f"Parsed JSON body is not a dictionary. Actual type: {type(req_body)}")
                return func.HttpResponse(
                    "Please pass a valid JSON body containing a base64 encoded PDF string.",
                    status_code=400
                )

            # Extract base64_string from the JSON body - now looking for 'body' field
            base64_string = req_body.get('body')
            if not base64_string:
                logging.warning("No 'body' field found in JSON request body.")
                return func.HttpResponse(
                    "Please pass a base64 encoded PDF string in the request body.",
                    status_code=400
                )

        except json.JSONDecodeError:
            # Assume the raw body is the base64-encoded PDF directly if not valid JSON
            logging.info("Request body is not JSON. Treating raw body as the base64-encoded PDF string.")
            base64_string = raw_body.decode('utf-8')

        # Remove data URI prefix if present
        if base64_string.startswith('data:'):
            base64_string = base64_string.split(",")[1]

        # Decode the base64 string to get PDF content in bytes
        pdf_bytes = base64.b64decode(base64_string)
        logging.info("Successfully decoded base64 string into PDF bytes.")
        
        # Extract text from PDF bytes
        cleaned_text = extract_and_clean_pdf_text(pdf_bytes)
        logging.info("Text extraction and cleaning completed successfully.")

        # Return the extracted text
        return func.HttpResponse(cleaned_text, status_code=200)

    except base64.binascii.Error as decode_error:
        logging.error(f"Base64 decoding failed: {decode_error}")
        return func.HttpResponse(
            "Invalid base64 encoded string.",
            status_code=400
        )

    except Exception as e:
        logging.error(f"Error occurred while extracting text: {str(e)}")
        logging.debug(f"Full exception traceback: {traceback.format_exc()}")
        return func.HttpResponse(
            f"An error occurred: {str(e)}",
            status_code=500
        )

def extract_and_clean_pdf_text(pdf_bytes):
    """
    Extracts text from a PDF bytes object and performs basic cleanup.
    :param pdf_bytes: PDF file content in bytes
    :return: Extracted and cleaned text from the PDF
    """
    pdf_file_like = BytesIO(pdf_bytes)

    # Extract text from the PDF using pdfminer
    try:
        logging.info("Extracting text from PDF.")
        extracted_text = extract_text(pdf_file_like)
        logging.debug(f"Extracted text length: {len(extracted_text)} characters.")
    except Exception as e:
        logging.error(f"Failed to extract text from PDF: {str(e)}")
        raise

    # Clean up the extracted text
    logging.info("Cleaning up extracted text.")
    try:
        # Remove any non-printable characters and excessive whitespace
        cleaned_text = re.sub(r'[^\x20-\x7E\n\r]+', '', extracted_text)  # Remove non-printable characters
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()  # Replace multiple whitespaces/newlines with a single space
        logging.debug(f"Cleaned text length: {len(cleaned_text)} characters.")
    except Exception as e:
        logging.error(f"Failed during text cleanup: {str(e)}")
        raise

    return cleaned_text
