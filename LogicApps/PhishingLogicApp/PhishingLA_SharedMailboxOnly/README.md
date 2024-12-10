
# User Submitted Phishing Analysis with Security Copilot - Shared Inbox Configuration Only

Author: Craig Freyman

This solution automates the analysis of user-submitted phishing emails using Security Copilot. It is highly flexible and supports integration with or without Microsoft Defender for Office 365 Report Phishing capability.

---

## Features

- **Automated Phishing Analysis**: Processes user-submitted phishing emails in real time.
- **Office 365 Integration**: Monitors a shared mailbox for email submissions.
- **Behavioral and Psychological Analysis**: Detects sophisticated phishing attempts by analyzing behavioral and psychological traits.
- **HTML Report Generation**: Produces detailed HTML reports summarizing email analysis.
- **Sentinel/Defender Integration**: Updates incidents with detailed analysis, including email and security insights.

---

## Deploy the Solution

### Step 1: Deploy the Function App

Click the button below to deploy the Function App. Provide a unique Function App name and select a resource group. Ensure the Function App is fully deployed before proceeding with the Logic App deployment.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Fmain%2FLogicApps%2FPhishingLogicApp%2FPhishingLA_Sentinel_Comments%2Ffunctionapp_azuredeploy.json)

Alternatively, use the command line:
```bash
az functionapp deployment source config-zip --resource-group yourresourcegroup --name youremptyfunctionapp --src .\FunctionApp.zip
```

---

### Step 2: Deploy the Logic App

Click the button below to deploy the Logic App. Input the following parameters during deployment:

- **SubscriptionId**: The Azure subscription ID for resource deployment.
- **LogicAppName**: The Logic App name.
- **ManagedServiceIdentity**: The User-Assigned Managed Identity (UAMI) for permissions.
- **ManagedServiceIdentityResourceGroup**: The resource group containing the UAMI.
- **FunctionAppName**: The previously deployed Azure Function App.
- **FunctionAppResourceGroup**: The resource group where the Function App is deployed.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FPhishingLogicApp%2FPhishingLA_SharedMailboxOnly%2Flogicapp_azuredeploy.json)

---

## Workflow Overview

1. **Mailbox Monitoring**: Listens for new emails in the shared mailbox.
2. **Email Parsing**: Extracts sender, recipient, URLs, attachments, and other details.
3. **Security Analysis**: Uses Security Copilot for in-depth email classification.
4. **HTML Report Generation**: Creates structured HTML reports.
5. **Sentinel Updates**: Updates Sentinel incidents with analysis results.

---

## Configuration Steps

1. **Initialize API Connections**:
   - Office 365
   - Security Copilot

2. **Enable the Logic App**:
   - Start the Logic App to process incoming emails.

3. **Update Permissions**:
   - Assign the Managed Identity required permissions (e.g., Reader, Microsoft Sentinel Reader).

4. **Function App Customization** (Optional):
   - Modify the Function App code if necessary.
   - Package and deploy updates.

---

## Example Outputs

### JSON Analysis Report
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

---

For more details, visit the [GitHub repository](https://github.com/cd1zz/securitycopilot).
