import logging
import azure.functions as func
from typing import List, Dict, Any

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        # Parse the JSON object from the request
        virus_total_data = req.get_json()

        # Extract the last_analysis_results from the data
        last_analysis_results = virus_total_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

        # Find results with category 'malicious'
        malicious_or_suspicious_results = [
            {
                "engine_name": result['engine_name'],
                "method": result['method'],
                "result": result['result']
            }
            for result in last_analysis_results.values()
            if result['category'] in ['malicious', 'suspicious']
        ]

        return func.HttpResponse(
            body=str(malicious_or_suspicious_results),
            status_code=200
        )
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return func.HttpResponse(
            body="An error occurred while processing the request.",
            status_code=500
        )
