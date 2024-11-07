import base64
import re
from pdfminer.high_level import extract_text
from io import BytesIO
import logging
import azure.functions as func

# Azure Function entry point
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing request to extract text from PDF.")
    
    # Extract base64 PDF string from request
    base64_string = req.params.get('base64_string')
    logging.debug(f"Extracted base64_string from params: {base64_string[:30]}..." if base64_string else "No base64_string found in params.")
    
    if not base64_string:
        try:
            req_body = req.get_json()
            logging.debug("Extracted request body successfully.")
        except ValueError as e:
            logging.error(f"Failed to parse JSON body: {str(e)}")
            return func.HttpResponse(
                "Please pass a base64 encoded PDF string in the request",
                status_code=400
            )
        else:
            base64_string = req_body.get('base64_string')
            logging.debug(f"Extracted base64_string from JSON body: {base64_string[:30]}..." if base64_string else "No base64_string found in JSON body.")

    if not base64_string:
        logging.warning("No base64_string found in request parameters or body.")
        return func.HttpResponse(
            "Please pass a base64 encoded PDF string in the request",
            status_code=400
        )

    try:
        logging.info("Starting text extraction from base64 string.")
        # Extract the text from the base64 string
        cleaned_text = extract_and_clean_pdf_text(base64_string)
        logging.info("Text extraction and cleaning completed successfully.")

        # Return extracted text
        return func.HttpResponse(cleaned_text, status_code=200)
    except Exception as e:
        logging.error(f"Error occurred while extracting text: {str(e)}")
        return func.HttpResponse(
            f"An error occurred: {str(e)}",
            status_code=500
        )

def extract_and_clean_pdf_text(base64_string):
    """
    Decodes a base64 encoded PDF, extracts text, and performs basic cleanup.
    :param base64_string: Base64 encoded PDF string
    :return: Extracted and cleaned text from the PDF
    """
    logging.debug("Decoding base64 encoded PDF data.")
    # Decode base64 string to binary PDF data
    try:
        pdf_data = base64.b64decode(base64_string)
        logging.debug("Base64 decoding successful.")
    except Exception as e:
        logging.error(f"Failed to decode base64 string: {str(e)}")
        raise

    pdf_file_like = BytesIO(pdf_data)

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
