import json
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

    # Iterate through each JSON in the list and generate HTML
    for index, json_data in enumerate(json_list):
        logging.info(f"Processing JSON object at index {index}.")
        try:
            # Handle Final Evaluation section
            if "FinalEvaluation" in json_data:
                logging.info("Adding Final Evaluation section to HTML report.")
                final_evaluation = json_data["FinalEvaluation"]
                html_content += "<div class='section'>"
                html_content += "<h2>Final Evaluation</h2>"
                html_content += f"<p><strong>Classification:</strong> <span class='badge badge-high'>{final_evaluation['Classification']}</span></p>"
                html_content += f"<p><strong>Confidence Level:</strong> <span class='badge badge-high'>{final_evaluation['ConfidenceLevel']}</span></p>"
                html_content += "<h3>Reasoning:</h3><ul>"
                for indicator in final_evaluation['Reasoning']['IndicatorsSummary']:
                    html_content += f"<li><i class='fas fa-exclamation-circle'></i> {indicator}</li>"
                html_content += "</ul>"
                html_content += f"<p><strong>Domain Reputation Summary:</strong> {final_evaluation['Reasoning']['DomainReputationSummary']}</p>"
                html_content += f"<p><strong>URL Findings Summary:</strong> {final_evaluation['Reasoning']['URLFindingsSummary']}</p>"
                html_content += f"<p><strong>Overall Assessment Summary:</strong> {final_evaluation['Reasoning']['OverallAssessmentSummary']}</p>"
                html_content += "</div>"

            # Handle Domain and URL Evaluation section
            if "DomainVerification" in json_data:
                logging.info("Adding Domain and URL Evaluation section to HTML report.")
                domain_verification = json_data["DomainVerification"]
                html_content += "<div class='section'>"
                html_content += "<h2>Domain and URL Evaluation</h2>"
                html_content += f"<p><strong>Sender Domain:</strong> {domain_verification['SenderDomain']}</p>"
                html_content += f"<p><strong>Reputation Level:</strong> <span class='badge badge-high'>{domain_verification['ReputationLevel']}</span></p>"
                html_content += f"<p><strong>Reputation Score:</strong> {domain_verification['ThreatIntelligence']['ReputationScore']}</p>"
                if "URLEvaluation" in json_data:
                    logging.info("Adding URL Evaluation details to HTML report.")
                    url_evaluation = json_data["URLEvaluation"]
                    html_content += "<h3>URLs Found:</h3><table>"
                    html_content += "<tr><th>URL</th><th>Reputation</th><th>Matches Domain</th></tr>"
                    for url in url_evaluation['URLsFound']:
                        html_content += f"<tr><td>{url['URL']}</td><td>{url['Reputation']}</td><td>{'Yes' if url['MatchesDomain'] else 'No'}</td></tr>"
                    html_content += "</table>"
                    html_content += f"<p><strong>Overall URL Assessment:</strong> {url_evaluation['OverallURLAssessment']}</p>"
                html_content += "</div>"

            # Handle Email Body Analysis section
            if "EmailBodyAnalysis" in json_data:
                logging.info("Adding Email Body Analysis section to HTML report.")
                email_body_analysis = json_data["EmailBodyAnalysis"]
                html_content += "<div class='section'>"
                html_content += "<h2>Email Body Analysis</h2>"
                html_content += f"<p><strong>Intent Summary:</strong> {email_body_analysis['IntentSummary']}</p>"
                html_content += "<h3>Phishing Indicators:</h3><ul>"
                for indicator in email_body_analysis['PhishingIndicators']:
                    html_content += f"<li><i class='fas fa-exclamation-circle'></i> {indicator}</li>"
                html_content += "</ul>"
                html_content += f"<p><strong>Overall Phishing Likelihood:</strong> <span class='badge badge-high'>{email_body_analysis['OverallPhishingLikelihood']}</span></p>"
                html_content += "</div>"

        except KeyError as e:
            logging.error(f"Missing expected key in JSON object at index {index}: {e}")
        except Exception as e:
            logging.error(f"An error occurred while processing JSON object at index {index}: {e}")

    # HTML Footer
    html_content += """
    </body>
    </html>
    """

    logging.info("HTML report creation complete.")
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
