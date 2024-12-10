# User Submitted Phishing Analysis with Security Copilot
Author: Craig Freyman

This solution automates the analysis of user submitted phishing emails using Security Copilot. It is highly flexible and can work with or without integration with Microsoft Defender for Office 365 Report Phishing capability. 

### **Integration with Defender (Optional)**
If Microsoft Defender for Office 365 is used, emails reported by users via the **Report Phishing** button are forwarded to a configured shared mailbox, and Defender creates an associated incident. This Logic App can monitor that shared mailbox, process the submitted emails, and automatically add the analysis results to the associated Defender or Sentinel incidents. The mailbox configuration can be set up in Defender by following the guidelines [here](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox).

### **Standalone Email Reporting**
For environments without Microsoft Defender or the **Report Phishing** functionality, this solution can be configured to analyze emails sent to any shared mailbox. After processing, the Logic App generates an HTML report and emails the results to a specified address, without the need for Defender or Sentinel integration.

### **Behavioral and Psychological Analysis**
This solution does not rely on threat intelligence or typical indicators of compromise, as these are already handled by your email gateway and security products. Instead, it focuses on analyzing the behavioral and psychological traits of the email, primarily based on the content and structure of the email body. This allows for detecting sophisticated phishing attempts that evade traditional signature or indicator-based defenses.

This flexibility allows organizations to deploy the solution in a variety of configurations based on their existing security infrastructure.

---

## Features

- **Automated Phishing Analysis**: Processes user-submitted phishing emails in real time.
- **Integration with Office 365**: Monitors a shared mailbox for new email submissions.
- **Advanced Email Analysis**: Leverages Security Copilot to detect phishing, spam, and suspicious communications.
- **HTML Report Generation**: Produces structured HTML reports for email analysis.
- **Integration with Sentinel/Defender**: Updates incidents with detailed analysis, including links to related data.

---

## Deploy the Solution

### Step 1: Deploy the Function App

Click the button below to deploy the Function App. Provide a unique Function App name and select a resource group. Ensure the Function App is fully deployed before proceeding with the Logic App deployment.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Fmain%2FPhishingLogicApp%2FPhishingLA_Sentinel_Comments%2Ffunctionapp_azuredeploy.json)

If needed, you can deploy the Function App manually using the command line:
```bash
az functionapp deployment source config-zip --resource-group yourresourcegroup --name youremptyfunctionapp --src .\FunctionApp.zip
```
Download the ZIP file before running this command.

### Step 2: Deploy the Logic App

Click the button below to deploy the Logic App. You will be prompted to input the following parameters during deployment:

- **SubscriptionId**: The Azure subscription ID where the resources will be deployed.
- **LogicAppName**: The name you want to assign to the Logic App.
- **IntegrationAccountName**: The name of the Integration Account to link with the Logic App. This is required for running inline code, such as regex parsing.
- **ManagedServiceIdentity**: The name of the User-Assigned Managed Identity (UAMI) that provides the Logic App with necessary permissions. This must be created prior to deployment and assigned the "Reader" and "Microsoft Sentinel Reader" roles.
- **ManagedServiceIdentityResourceGroup**: The name of the resource group where the Managed Identity is located.
- **FunctionAppName**: The name of the Azure Function App created earlier, which will be called by the Logic App.
- **FunctionAppResourceGroup**: The name of the resource group where the Function App is deployed.
- **LogAnalyticsWorkspaceName**: The name of the Log Analytics Workspace associated with Sentinel.
- **LogAnalyticsWorkspaceId**: The workspace ID of the Log Analytics Sentinel Workspace.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FPhishingLogicApp%2FPhishingLA_Sentinel_Comments%2Flogicapp_azuredeploy.json)

#### Notes:
1. Ensure that all prerequisite resources, such as the Managed Identity, Integration Account, and Function App, are created and configured before deploying the Logic App.
2. If you encounter issues during deployment, double-check the parameter values for accuracy and ensure that permissions are correctly configured.

---

## Workflow Overview

### **Logic App Workflow Details**

1. **Mailbox Monitoring**: Monitors a shared Office 365 mailbox and triggers on new email arrivals.
2. **Email Parsing**: Extracts key details like sender, recipient, subject, URLs, and attachments.
3. **Security Analysis**: Leverages Security Copilot to classify emails and identify phishing attempts.
4. **HTML Report**: Creates a detailed HTML report summarizing the analysis.
5. **Incident Updates**: Updates Sentinel incidents with the report, including a timestamp and AI-generated disclaimer.

---

### **Core Analysis Process**

#### Behavioral Triggers Analysis
- Identifies coercive language or emotional triggers.
- Evaluates alignment with the email's stated purpose.

#### Logical Coherence
- Assesses content consistency and plausibility.
- Flags contradictions, vagueness, or illogical requests.

#### Contextual Integrity
- Evaluates formatting, terminology, and attachment relevance.
- Detects placeholder-like data or unrealistic content.

#### Intent Verification
- Infers the sender's likely intent and evaluates potential risks.

#### URL and Attachment Analysis
- Categorizes URLs and analyzes their alignment with trusted domains.
- Assesses attachments for relevance and security risks.

#### Final Classification
- Categorizes emails as **Phishing**, **Junk/Spam**, **Legitimate**, or **Suspicious**.

---

## Configuration Steps

### 1. Initialize API Connections
- Open the Logic App and configure the following API connections:
  - **Office 365**
  - **Security Copilot**
  - **Azure Sentinel**
  - **Conversion Service**

### 2. Enable the Logic App
- Ensure the Logic App is enabled to start processing emails.

### 3. Update Permissions
- Assign the Managed Service Identity (UAMI) required permissions, such as:
  - **Reader**
  - **Microsoft Sentinel Reader**

### 4. Function App Customization (Optional)
- Modify the Function App code if necessary.
- Repackage it into a `.zip` file for deployment, ensuring all dependencies are included.

---

## Example Output

### Structured JSON Report
The following is an example of the JSON output generated by Security Copilot during the analysis:
```json
{
  "email_summary": {
    "subject": "Urgent Payment Request",
    "content_summary": "Request to approve a wire transfer."
  },
  "behavioral_triggers": {
    "tone": "Urgent",
    "alignment_with_purpose": "FALSE"
  },
  "logical_coherence": {
    "is_consistent": "FALSE",
    "contradictions": ["Mismatch between sender domain and content."]
  },
  "contextual_integrity": {
    "plausibility": "FALSE",
    "issues": ["Suspicious domain in URL."]
  },
  "intent_verification": {
    "likely_intent": "Phishing",
    "risk_assessment": "High"
  },
  "final_assessment": {
    "category": "Phishing",
    "rationale": "Clear indicators of malicious intent."
  }
}
```

### HTML Report
An HTML version of the report is emailed to the recipient and included in Sentinel incident comments.

---

## Notes
- Regularly review and update the Function App code to maintain compatibility with dependencies.
- Ensure all necessary API connections and permissions are properly configured.
- For manual deployments, confirm the Logic App uses the correct Function App and managed identity.

For questions or troubleshooting, please refer to the [GitHub repository](https://github.com/cd1zz/securitycopilot) for documentation and support.
