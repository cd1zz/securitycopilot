import json
import logging
import azure.functions as func
import tiktoken

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.basicConfig(level=logging.DEBUG)  # Set logging level to DEBUG for detailed logs
    logging.info("Token length calculation function triggered.")

    try:
        # Parse the incoming JSON request
        req_body = req.get_json()
        logging.debug(f"Request body: {req_body}")

        input_text = req_body.get("input_text")
        model = req_body.get("model", "gpt-4")  # Default to 'gpt-4' if model is not specified

        if not input_text:
            logging.warning("Missing 'input_text' in the request body.")
            return func.HttpResponse(
                "Missing 'input_text' in the request body.",
                status_code=400
            )

        # Initialize the tokenizer for the specified model
        try:
            logging.debug(f"Initializing tokenizer for model: {model}")
            tokenizer = tiktoken.encoding_for_model(model)
        except KeyError as ke:
            logging.error(f"Model '{model}' is not supported: {ke}")
            return func.HttpResponse(
                f"Model '{model}' is not supported.",
                status_code=400
            )

        # Tokenize the input text and calculate token length
        tokens = tokenizer.encode(input_text)
        token_length = len(tokens)
        logging.debug(f"Tokenized input: {tokens}, Token length: {token_length}")

        # Return the token length as a JSON response
        response = {
            "token_length": token_length,
            "model": model
        }
        logging.info("Token length calculation successful.")
        return func.HttpResponse(json.dumps(response), status_code=200, mimetype="application/json")

    except Exception as e:
        logging.exception("An unexpected error occurred.")
        return func.HttpResponse(
            f"An error occurred while processing the request: {str(e)}",
            status_code=500
        )
