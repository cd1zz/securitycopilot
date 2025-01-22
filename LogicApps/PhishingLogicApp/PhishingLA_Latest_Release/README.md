# User Submitted Phishing Analysis with Security Copilot
**Author:** Craig Freyman

This solution streamlines phishing email analysis by leveraging a shared mailbox, Azure Logic Apps, and Security Copilot. It monitors a shared Office 365 mailbox for submitted emails, parses their content, and conducts detailed security analysis. Security insights, including behavioral triggers, contextual integrity, and attachment/URL assessments, are used to classify emails as Phishing, Junk/Spam, Legitimate, or Suspicious. Results are logged to Microsoft Sentinel, and an HTML report is emailed to the designated recipient. The deployment is designed for ease of use, leveraging system-managed identities and minimal manual configuration, while ensuring compatibility with Azure best practices.

---

## Prerequisites

1. **Shared Mailbox**: Create a shared mailbox to monitor for submitted phishing emails. Follow the instructions here: [Create a Shared Mailbox](https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-mailbox?view=o365-worldwide).
2. **Azure CLI Installed**: Ensure the Azure CLI is installed and configured with access to your subscription. Refer to the [Azure CLI documentation](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) for setup instructions. (Optional)
3. **Microsoft Sentinel Workspace**: Have a Microsoft Sentinel workspace created and configured with proper access permissions. (Optional)
4. **Permissions**: Ensure the necessary permissions are granted to the system-managed identity and user-assigned managed identity (if used) for accessing resources such as:
   - Azure Monitor Logs
   - Microsoft Sentinel
   - Graph API (`Directory.Read.All`)
5. **Azure Details**:
- **SubscriptionId**: Azure subscription ID for deployment.
- **LogicAppName**: Name of the Logic App.
- **FunctionAppName**: Name of the deployed Function App.
- **FunctionAppResourceGroup**: Resource group of the Function App.
- **LogAnalyticsWorkspaceName**: Name of the Log Analytics Workspace for Sentinel. (Optional, use "none" if not in use)
- **LogAnalyticsWorkspaceId**: Workspace ID for Sentinel. (Optional, use "none" if not in use)
- **LogAnalyticsResourceGroup**: Resource group of Log Analytics. (Optional, use "none" if not in use)
- **SharedMailboxAddress**: Shared O365 mailbox email address.
- **HTMLReportRecipient**: Recipient email address for the HTML report.
---

## Step 1: Deploy the Function App

Click the button below to deploy the Function App. This deployment creates:
- A Function App with system-managed identity.
- A storage account for Function App resources.
- An Application Insights resource for monitoring.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FPhishingLogicApp%2FPhishingLA_Latest_Release%2Ffunctionapp_azuredeploy.json)

### Manual Deployment

If needed, deploy the Function App manually:
1. Download the ZIP file for the Function App: [FunctionApp.zip](https://github.com/cd1zz/securitycopilot/raw/refs/heads/main/FunctionApps/ParseEmailFunctionApp/ParseEmailFunctionApp.zip)
2. Run the following command in the Azure CLI:
   ```bash
   az functionapp deployment source config-zip --resource-group yourResourceGroup --name yourFunctionAppName --src .\ParseEmailFunctionApp.zip
   ```

---

## Step 2: Deploy the Logic App

Click the button below to deploy the Logic App. Provide the required parameters during deployment:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FPhishingLogicApp%2FPhishingLA_Latest_Release%2Flogicapp_azuredeploy.json)

### Parameters
- **SubscriptionId**: Azure subscription ID for deployment.
- **LogicAppName**: Name of the Logic App.
- **FunctionAppName**: Name of the deployed Function App.
- **FunctionAppResourceGroup**: Resource group of the Function App.
- **LogAnalyticsWorkspaceName**: Name of the Log Analytics Workspace for Sentinel.
- **LogAnalyticsWorkspaceId**: Workspace ID for Sentinel.
- **LogAnalyticsResourceGroup**: Resource group of Log Analytics.
- **SharedMailboxAddress**: Shared O365 mailbox email address.
- **HTMLReportRecipient**: Recipient email address for the HTML report.

---

## Step 3: Enable API Connections

1. Open the Logic App Designer in Azure Portal.
2. Enable these connections:
   - **Office 365 Shared Inbox**: Authorize with a member account of the shared mailbox.
   - **Security Copilot**: Authorize with an account with Security Copilot access.
   - **Azure Monitor Logs Actions**: Assign to your managed identity and provision proper permissions.
   - **Sentinel Actions**: Assign to your managed identity and provision proper permissions.

---

## Step 4: Enable the Logic App

The Logic App is deployed in a disabled state. Enable it in the Logic App Overview when ready to test.

---

## Workflow Overview

### Logic App Workflow
1. Monitors a shared Office 365 mailbox for new emails.
2. Parses email content for sender, recipient, URLs, and attachments.
3. Analyzes potential phishing threats with Security Copilot.
4. Generates a detailed HTML report.
5. Updates Sentinel incidents with analysis results.

---

## Notes

1. **Security Considerations**:  
   - **Function App**: The Function App is configured to run from a storage account. Ensure the storage account has secure access enabled and no unnecessary public access.
   - **Storage Accounts**: Disable public access and enforce private endpoint connections to secure data. Rotate access keys regularly.
   - **Logic Apps**: The Logic App runs with a system-managed identity. Ensure it has the minimum required permissions to access resources like Office 365, Microsoft Sentinel, and Azure Monitor Logs.
   - **Data Sensitivity**: Email content, including attachments and URLs, is processed by the Function App and Logic App. Ensure compliance with corporate security policies for sensitive data.
   - **API Connections**: Use managed identity for API connections wherever possible to avoid credential leakage.
2. **Deployment Ease vs. Security**: This solution is designed for easy deployment and integration but may not align with the highest security standards. Review and adjust configurations as needed to comply with corporate security policies.
3. **Regular Maintenance**: Regularly update the Function App code to ensure compatibility with dependencies and address potential security vulnerabilities.

---

Let me know if further refinements or additional details are needed.