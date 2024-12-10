# Daily Security Briefing Logic App

This Logic App automates the creation and delivery of a daily security update, summarizing high-severity incidents, threat intelligence, newly discovered critical CVEs, and risky users. The generated HTML report is dynamically updated with the latest data and emailed to the specified recipient.

## Features

- **High Severity Incidents:** Retrieves and summarizes high-severity incidents from Security Copilot.
- **Threat Intelligence:** Identifies threats based on exposure scores.
- **Critical CVEs:** Highlights the top five critical CVEs recently published.
- **Risky Users:** Identifies and reports on the riskiest users within your organization.
- **HTML Report:** Creates a polished HTML summary of all findings.
- **Automated Email Delivery:** Sends the daily report via email.

## Prerequisites

1. **Azure Subscription:** Ensure you have an active Azure subscription.
2. **Connections:**
   - Office 365 for email delivery. Created on deployment. 
   - Security Copilot for data retrieval and analysis. Security Copilot and SCUs must already be provisioned. 
3. **Parameters:**
   - `LogicAppName`: The name of the Logic App.
   - `ReportEmailedTo`: The email address to send the report.
   - `SubscriptionId`: The subscription ID where resources are deployed.

## Deployment

To deploy the Daily Security Briefing Logic App, click the button below:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FDailySecurityDigestLogicApp%2Fsecuritydigest_logicapp_azuredeploy.json)

## Post-Deployment Configuration

1. Navigate to the Azure Portal and open your newly deployed Logic App.
2. Configure the necessary API connections:
   - **Office 365 Connection:** Provide the necessary credentials to enable email delivery.
   - **Security Copilot Connection:** Authenticate to retrieve incident and threat data.
3. Update the Logic App parameters if needed:
   - Recipient email address (`ReportEmailedTo`).
   - Logic App name (`LogicAppName`).

## Logic App Workflow

1. **Trigger:** Runs every 24 hours.
2. **High Severity Incidents:** Fetches and summarizes high-severity incidents.
3. **Threat Intelligence:** Identifies threats based on exposure scores.
4. **Critical CVEs:** Highlights critical CVEs.
5. **Risky Users:** Lists and details risky users.
6. **HTML Report Generation:** Creates a structured HTML report using a predefined template.
7. **Email Delivery:** Sends the report to the configured recipient.

## HTML Report Structure

The report contains the following sections:
- **High Severity Incidents:** Key details of incidents, including ID, description, status, and findings.
- **Threat Intelligence Updates:** Top threats and their details.
- **Critical CVEs:** Recent CVEs with severity and mitigation details.
- **Risky Users:** Identifies riskiest users with actionable insights.

## Customization

Modify the Logic App workflow in the Azure Portal to:
- Add additional data sources.
- Customize the email format or content.
- Adjust the report's HTML template.

## Support

For issues or questions, please create an issue in the [GitHub repository](https://github.com/cd1zz/securitycopilot).
