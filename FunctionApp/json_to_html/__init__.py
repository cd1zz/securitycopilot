import logging
from jinja2 import Template
import azure.functions as func

def create_html(json_data):

    # Define HTML structure using the provided CSS
    html_template = '''
    <html>
    <head>
        <style>
            body {
                font-family: Aptos, sans-serif;
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
        {% set section_order = ['FinalEvaluation', 'EmailBodyAnalysis', 'AttachmentReview', 'DomainEvaluation', 'URLEvaluation'] %}
        {% for section in section_order %}
            {% for item in json_data %}
                {% if section in item %}
                    {% set value = item[section] %}
                    {% if section == 'FinalEvaluation' %}
                    <div class='section'>
                        <h2>Final Evaluation</h2>
                        <p><strong>Classification:</strong> 
                            <span style="
                                {% if value.Classification == 'PHISHING' %}
                                    background-color: #d9534f;
                                {% elif value.Classification == 'SUSPICIOUS' %}
                                    background-color: #f0ad4e;
                                {% elif value.Classification == 'BENIGN' %}
                                    background-color: #5bc0de;
                                {% else %}
                                    background-color: #cccccc; /* Default color */
                                {% endif %}
                                color: white; padding: 5px 10px; border-radius: 3px; display: inline-block;">
                                {{ value.Classification }}
                            </span>
                        </p>
                        <p><strong>Confidence Level:</strong> 
                            <span style="
                                {% if value.ConfidenceLevel == 'High' %}
                                    background-color: #0033cc;
                                {% elif value.ConfidenceLevel == 'Medium' %}
                                    background-color: #4d79ff;
                                {% elif value.ConfidenceLevel == 'Low' %}
                                    background-color: #b3c6ff;
                                {% else %}
                                    background-color: #cccccc; /* Default color */
                                {% endif %}
                                color: white; padding: 5px 10px; border-radius: 3px; display: inline-block;">
                                {{ value.ConfidenceLevel }}
                            </span>
                        </p>
                        <p><strong>🔍 Overall Assessment Summary:</strong> {{ value.OverallAssessmentSummary }}</p>
                    </div>
                    {% elif section == 'EmailBodyAnalysis' %}
                    <div class='section'>
                        <h2>Email Body Analysis</h2>
                        <p><strong>✉️ Email Purpose Summary:</strong> {{ value.EmailPurposeSummary }}</p>
                        <p><strong>Intent Summary:</strong> {{ value.IntentSummary }}</p>

                        <h3>Phishing Indicators:</h3>
                        <ul>
                            {% for indicator in value.PhishingIndicators %}
                            <li>⚠️ {{ indicator }}</li>
                            {% endfor %}
                        </ul>
                        {% if value.PositiveIndicators is defined %}
                        <h3>Positive Indicators:</h3>
                        <ul>
                            {% for indicator in value.PositiveIndicators %}
                            <li>✔️ {{ indicator }}</li>
                            {% endfor %}
                        </ul>
                        {% endif %}
                        <p><strong>Overall Phishing Likelihood:</strong> 
                            <span style="
                                {% if value.OverallPhishingLikelihood == 'High' %}
                                    background-color: #4d79ff;
                                {% elif value.OverallPhishingLikelihood == 'Medium' %}
                                    background-color: #4d79ff;
                                {% elif value.OverallPhishingLikelihood == 'Low' %}
                                    background-color: #b3c6ff;
                                {% else %}
                                    background-color: #cccccc; /* Default color */
                                {% endif %}
                                color: white; padding: 5px 10px; border-radius: 3px; display: inline-block;">
                                {{ value.OverallPhishingLikelihood }}
                            </span>
                        </p>
                    </div>
                    {% elif section == 'AttachmentReview' %}
                    <div class='section'>
                        <h2>Attachment Review</h2>
                        <p><strong>📎 Findings:</strong> {{ value.Findings }}</p>
                        <p><strong>Legitimacy Check:</strong> {{ value.LegitimacyCheck }}</p>
                    </div>
                    {% elif section == 'DomainEvaluation' %}
                    <div class='section'>
                        <h2>Domain Evaluation</h2>
                        <p><strong>Overall Domain Assessment:</strong> {{ value.OverallDomainAssessment }}</p>
                        <h3>🌐 Domains Found:</h3>
                        <table>
                            <tr>
                                <th>Domain</th>
                                <th>Reputation</th>
                                <th>Aligned With Email Intent</th>
                            </tr>
                            {% for domain in value.DomainsFound %}
                            <tr>
                                <td>{{ domain.Domain }}</td>
                                <td>{{ domain.Reputation }}</td>
                                <td>{{ domain.AlignedWithEmailIntent }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% elif section == 'URLEvaluation' %}
                    <div class='section'>
                        <h2>🔗 URL Evaluation</h2>
                        <p><strong>Overall URL Assessment:</strong> {{ value.OverallUrlAssessment }}</p>
                        <h3>URLs Found:</h3>
                        <table>
                            <tr>
                                <th>URL</th>
                                <th>Reputation</th>
                                <th>Aligned With Email Intent</th>
                                <th>Redirections</th>
                            </tr>
                            {% for url in value.URLsFound %}
                            <tr>
                                <td>{{ url.URL }}</td>
                                <td>{{ url.Reputation }}</td>
                                <td>{{ url.AlignedWithEmailIntent }}</td>
                                <td>{{ url.Redirections }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endif %}
                {% endif %}
            {% endfor %}
        {% endfor %}
    </body>
    </html>
    '''
    # Use Jinja2 Template to render HTML with provided JSON data
    template = Template(html_template)
    rendered_html = template.render(json_data=json_data)

    return rendered_html

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
        html_report = create_html(req_body)

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
