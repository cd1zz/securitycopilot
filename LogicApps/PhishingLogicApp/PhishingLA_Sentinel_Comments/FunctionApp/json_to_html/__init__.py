import logging
from urllib.parse import unquote
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
            h3 {
                color: #2196F3;
                margin-top: 10px;
            }
            p {
                font-size: 1em;
            }
            ul {
                list-style-type: none;
                padding-left: 0;
            }

            ul li {
                margin: 5px 0;
            }

            .styled-list-item {
                border-left: 5px solid #2196F3;
                padding: 10px;
                margin: 5px 0;
                background: #e7f3fe;
                border-radius: 4px;
                word-break: break-word;
            }
            .section {
                margin-bottom: 30px;
                padding: 15px;
                background-color: #ffffff;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }
            .classification {
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
                display: inline-block;
                text-transform: uppercase;
            }

            .phishing {
                background-color: #d9534f; /* Red for malicious/phishing */
            }
            .junk-spam {
                background-color: #f0ad4e; /* Orange for junk/spam */
            }
            .legitimate {
                background-color: #5cb85c; /* Green for legitimate */
            }
            .suspicious {
                background-color: #f0ad4e; /* Yellow for suspicious */
            }
            .default {
                background-color: #cccccc; /* Gray for default/unknown */
            }
        </style>
    </head>
    <body>
        {% set section_order = [
            'final_assessment', 
            'email_summary', 
            'pretense_vs_intent_mapping', 
            'intent_verification', 
            'logical_coherence', 
            'behavioral_triggers', 
            'url_analysis', 
            'attachment_analysis', 
            'contextual_integrity', 
            'subtle_clue_detection'
        ] %}
        {% for section in section_order %}
            {% if section in json_data %}
                <div class='section'>
                    <h2>{{ section.replace('_', ' ').title() }}</h2>
                    
                    {% if 'description' in json_data[section] %}
                        <p><em>{{ json_data[section]['description'] }}</em></p>
                    {% endif %}
                    
                    {% if section == 'final_assessment' %}
                        <p>
                            <strong>Category:</strong>
                            <span class="classification{% if json_data[section]['category']|upper == 'PHISHING' %} phishing
                            {% elif json_data[section]['category']|upper == 'JUNK/SPAM' %} junk-spam
                            {% elif json_data[section]['category']|upper == 'LEGITIMATE' %} legitimate
                            {% elif json_data[section]['category']|upper == 'SUSPICIOUS' %} suspicious
                            {% else %} default{% endif %}">
                            {{ json_data[section]['category']|upper if json_data[section]['category'] else 'N/A' }}
                            </span>
                        </p>
                        <p><strong>Rationale:</strong> {{ json_data[section]['rationale'] if json_data[section]['rationale'] else 'N/A' }}</p>
                    {% else %}
                        {% for subkey, subvalue in json_data[section].items() %}
                            {% if subkey != 'description' %}
                                {% if subvalue is mapping %}
                                    <h3>{{ subkey.replace('_', ' ').title() }}</h3>
                                    <ul>
                                        {% for key, value in subvalue.items() %}
                                            {% if value is iterable and not value is string %}
                                                <li>
                                                    <strong>{{ key.replace('_', ' ').title() }}:</strong>
                                                    <ul>
                                                        {% if value|length > 0 %}
                                                            {% for item in value %}
                                                            <li class="styled-list-item">{{ item }}</li>
                                                            {% endfor %}
                                                        {% else %}
                                                            <li class="styled-list-item">N/A</li>
                                                        {% endif %}
                                                    </ul>
                                                </li>
                                            {% else %}
                                                <li>
                                                    <strong>{{ key.replace('_', ' ').title() }}:</strong> 
                                                    {{ value if value else 'N/A' }}
                                                </li>
                                            {% endif %}
                                        {% endfor %}
                                    </ul>
                                {% elif subvalue is iterable and not subvalue is string %}
                                    <h3><strong>{{ subkey.replace('_', ' ').title() }}:</strong></h3>
                                    <ul>
                                        {% if subvalue|length > 0 %}
                                            {% for item in subvalue %}
                                            <li class="styled-list-item">{{ item }}</li>
                                            {% endfor %}
                                        {% else %}
                                            <li class="styled-list-item">N/A</li>
                                        {% endif %}
                                    </ul>
                                {% else %}
                                    <p><strong>{{ subkey.replace('_', ' ').title() }}:</strong> {{ subvalue if subvalue else 'N/A' }}</p>
                                {% endif %}
                            {% endif %}
                        {% endfor %}
                    {% endif %}
                </div>
            {% endif %}
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
        if not isinstance(req_body, dict):
            logging.warning("Invalid input format. Expected a JSON objects.")
            return func.HttpResponse(
                "Invalid input format. Expected a JSON object.",
                status_code=400
            )

        # Generate HTML Report using the helper function
        html_report = create_html(req_body)
        html_report = unquote(html_report)

        # Return HTML Report as response
        logging.info("Returning generated HTML report.")
        return func.HttpResponse(
            html_report,
            status_code=200,
            mimetype="text/html",
            headers={
                "Content-Type": "text/html; charset=utf-8"
            }
        )

    except ValueError as e:
        logging.error(f"Invalid JSON input: {e}")
        raise e
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
