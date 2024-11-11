import logging
import azure.functions as func

def create_html_report_from_list(json_list):
    logging.info("Creating HTML report from the provided JSON list.")
    
    # Enhanced HTML Header with CSS
    html_content = """
    <html>
    <head>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                background-color: #f9f9f9;
                color: #333;
                margin: 20px;
            }
            h2 {
                color: #4CAF50;
                border-bottom: 2px solid #4CAF50;
                padding-bottom: 5px;
            }
            p {
                font-size: 1em;
            }
            ul {
                list-style-type: none;
                padding-left: 0;
            }
            ul li {
                background: #e7f3fe;
                padding: 10px;
                margin: 5px 0;
                border-left: 5px solid #2196F3;
                border-radius: 4px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                background-color: #fff;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 12px;
            }
            th {
                background-color: #4CAF50;
                color: white;
                text-align: left;
            }
            td {
                text-align: center;
            }
            .badge {
                display: inline-block;
                padding: 5px 10px;
                font-size: 0.9em;
                color: white;
                border-radius: 3px;
            }
            .badge-high {
                background-color: #d9534f;
            }
            .badge-medium {
                background-color: #f0ad4e;
            }
            .badge-low {
                background-color: #5bc0de;
            }
            .section {
                margin-bottom: 30px;
                padding: 15px;
                background-color: #ffffff;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }
        </style>
    </head>
    <body>
    """
    
    # Helper functions to generate HTML for each section
    def generate_domain_url_section(data):
        section_html = "<h2>Domain and URL Evaluation</h2><table>"
        section_html += "<tr><th>Sender Domain</th><th>Reputation Level</th><th>URLs Found</th><th>Overall URL Assessment</th></tr>"
        if "DomainVerification" in data and "URLEvaluation" in data:
            domain = data["DomainVerification"].get("SenderDomain", "N/A")
            reputation = data["DomainVerification"].get("ReputationLevel", "N/A")
            urls = data["URLEvaluation"].get("URLsFound", [])
            overall_assessment = data["URLEvaluation"].get("OverallURLAssessment", "N/A")
            urls_list = "<ul>" + "".join([f"<li>{url['URL']} (Reputation: {url['Reputation']})" for url in urls]) + "</ul>"
            section_html += f"<tr><td>{domain}</td><td>{reputation}</td><td>{urls_list}</td><td>{overall_assessment}</td></tr>"
        section_html += "</table><br><hr><br>"
        return section_html

    def generate_final_evaluation_section(data):
        section_html = "<h2>Final Evaluation</h2><table>"
        section_html += "<tr><th>Classification</th><th>Confidence Level</th><th>Reasoning Summary</th></tr>"
        if "FinalEvaluation" in data:
            classification = data["FinalEvaluation"].get("Classification", "N/A")
            confidence = data["FinalEvaluation"].get("ConfidenceLevel", "N/A")
            reasoning = data["FinalEvaluation"].get("Reasoning", {}).get("OverallAssessmentSummary", "N/A")
            section_html += f"<tr><td>{classification}</td><td>{confidence}</td><td>{reasoning}</td></tr>"
        section_html += "</table><br><hr><br>"
        return section_html

    def generate_email_body_analysis_section(data):
        section_html = "<h2>Email Body Analysis</h2><table>"
        section_html += "<tr><th>Email Purpose Summary</th><th>Intent Summary</th><th>Phishing Indicators</th><th>Overall Phishing Likelihood</th></tr>"
        if "EmailBodyAnalysis" in data:
            purpose = data["EmailBodyAnalysis"].get("EmailPurposeSummary", "N/A")
            intent = data["EmailBodyAnalysis"].get("IntentSummary", "N/A")
            indicators = data["EmailBodyAnalysis"].get("PhishingIndicators", [])
            indicators_list = "<ul>" + "".join([f"<li>{indicator}</li>" for indicator in indicators]) + "</ul>"
            likelihood = data["EmailBodyAnalysis"].get("OverallPhishingLikelihood", "N/A")
            section_html += f"<tr><td>{purpose}</td><td>{intent}</td><td>{indicators_list}</td><td>{likelihood}</td></tr>"
        section_html += "</table><br><hr><br>"
        return section_html

    # Iterate over JSON list and add content per section in the specified order
    for item in json_list:
        if "FinalEvaluation" in item:
            html_content += generate_final_evaluation_section(item)
        if "EmailBodyAnalysis" in item:
            html_content += generate_email_body_analysis_section(item)
        if "DomainVerification" in item or "URLEvaluation" in item:
            html_content += generate_domain_url_section(item)
    
    # Closing HTML tags
    html_content += """
    </body>
    </html>
    """
    
    logging.info("HTML report successfully created.")
    return html_content


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing request to generate phishing HTML report.')

    try:
        # Parse the request body
        req_body = req.get_json()
        logging.info("Request body successfully parsed.")

        # Validate the input is a list
        if not isinstance(req_body, list):
            logging.warning("Invalid input format. Expected a list of JSON objects.")
            return func.HttpResponse(
                "Invalid input format. Expected a list of JSON objects.",
                status_code=400
            )

        # Generate HTML Report using the helper function
        html_report = create_html_report_from_list(req_body)

        # Return HTML Report as response
        logging.info("Returning generated HTML report.")
        return func.HttpResponse(
            html_report,
            status_code=200,
            mimetype="text/html"
        )

    except ValueError as e:
        logging.error(f"Invalid JSON input: {e}")
        return func.HttpResponse(
            "Invalid JSON input.",
            status_code=400
        )

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(
            f"An internal error occurred: {e}",
            status_code=500
        )
