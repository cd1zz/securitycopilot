# User Submitted Phishing Analysis with Security Copilot
Author: Craig Freyman

This version uses a system managed identity created on the fly. 

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FPhishingLogicApp%2FPhishingLA_Sentinel_Comments_sysmng_identity%2Ffunctionapp_azuredeploy.json
)

If needed, you can deploy the Function App manually using the command line:
```bash
az functionapp deployment source config-zip --resource-group yourresourcegroup --name youremptyfunctionapp --src .\FunctionApp.zip
```
Download the ZIP file before running this command.

---

### Step 2: Deploy the Logic App

Click the button below to deploy the Logic App. You will be prompted to input the following parameters during deployment:

- **SubscriptionId**: The Azure subscription ID where the resources will be deployed.
- **LogicAppName**: The name of the Logic App to be deployed.
- **IntegrationAccountName**: The name of the Integration Account to link with the Logic App. Required for running inline code for regex purposes. Created during this deployment.
- **ManagedIdentityName**: The User-Assigned Managed Identity (UAMI) to provide permissions to resources. UAMI must be created prior to deployment. Grant 'Reader,' 'Microsoft Sentinel Reader,' and Graph API `Directory.Read.All` permissions.
- **ManagedIdentityResourceGroupName**: The resource group where the Managed Identity is located.
- **FunctionAppName**: The name of the Azure Function App created earlier, which will be called by the Logic App.
- **FunctionAppResourceGroup**: The name of the resource group where the Function App is deployed.
- **LogAnalyticsWorkspaceName**: The name of the Log Analytics Workspace associated with Sentinel.
- **LogAnalyticsWorkspaceId**: The workspace ID of the Log Analytics Sentinel Workspace.
- **LogAnalyticsResourceGroup**: The resource group name of the Log Analytics Sentinel Workspace.
- **SharedMailboxAddress**: Email address of the shared O365 mailbox.
- **DestinationForHTMLReport**: Email address where the HTML report should be sent.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FPhishingLogicApp%2FPhishingLA_Sentinel_Comments_sysmng_identity%2Flogicapp_azuredeploy.json
)

---

### Step 3: Enable API Connections

After deploying the Logic App, open the Logic App Designer in the Azure portal. Enable the following API connections:

1. **Office 365 Shared Inbox**
![alt text](image.png)

Authorize with an account that has been added as a member to the shared mailbox.
![alt text](image-1.png)

Save the connection and confirm Status:
![alt text](image-2.png)
2. **Security Copilot**
Authorize Security Copilot with an account that has been granted access to Security Copilot. Authorize, and Save the connection.
![alt text](image-3.png)

3. **Azure Monitor Logs Actions**
From the Logic App designer, confirm that the "Query to get systemalertid" is assigned to your managed identity and that there are no errors. 

4. **Sentinel Actions**
From the Logic App designer, confirm that the "Alert - Get incident from systemalertid" is assigned to your managed identity and that there are no errors. 

5. **Conversion Service**
No action needed.

---

### Step 4: Enable the Logic App

The Logic App is deployed in a disabled state. Go to the Logic App Overview and click the "Enable" button when you are ready to test.

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

## Notes

- Regularly review and update the Function App code to maintain compatibility with dependencies.
- Ensure all necessary API connections and permissions are properly configured.
- For manual deployments, confirm the Logic App uses the correct Function App and managed identity.

For questions or troubleshooting, please refer to the [GitHub repository](https://github.com/cd1zz/securitycopilot) for documentation and support.

