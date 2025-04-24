# Software Risk Review Automation

## Author: Craig Freyman

This solution automates Software Risk Reviews by integrating an Azure Logic App, Azure Function Apps, and a Microsoft Security Copilot Promptbook. It triggers on incoming emails that request a review, performs real-time web research using Azure OpenAI, and generates a security-oriented assessment of the software.

---

## Overview

1. **Trigger** on new emails to a shared mailbox with subject line: `SoftwareRiskReview: <SoftwareName>`
2. **Extract** the software name using regex in a Function App
3. **Enrich** with AI-powered web research (DuckDuckGo + Azure OpenAI)
4. **Submit** to Security Copilot for a risk evaluation using a Promptbook

---

## Email Format

To activate the workflow, send an email with the following subject format:

```
SoftwareRiskReview: Dovetail
```

No email attachments are required. The Logic App monitors a shared mailbox and uses only the subject line for input parsing.

---

## Deployment Instructions

Follow these steps in order to fully deploy the solution:

### 1. Deploy the Security Copilot Promptbook

Create a Promptbook following this guide:  
[Creating Promptbooks in Copilot for Security](https://rodtrent.substack.com/p/creating-promptbooks-in-copilot-for)

Prompt book prompts can be found here:


### 2. Retrieve the Promptbook ID

After creating the Promptbook:

- Open **Promptbook Library** in the Security Copilot interface
- Click your Promptbook to open it
- Copy the **GUID** from the browser’s address bar — this is required during Logic App deployment

Prompt definitions:  
[PromptBookPrompts.md](https://github.com/cd1zz/securitycopilot/blob/main/LogicApps/SoftwareRiskReview/PromptBookPrompts.md)

---

### 3. Create Azure OpenAI Resource

```powershell
az cognitiveservices account create `
  --name thenameofyourinstance `
  --resource-group yourresourcegroup `
  --kind OpenAI `
  --sku S0 `
  --location yourresourcegrouplocation `
  --custom-domain youruniquecustomsubdomain `
  --yes
```

Reference: [az cognitiveservices account create](https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account?view=azure-cli-latest#az-cognitiveservices-account-create)

---

### 4. Deploy a Model (e.g., `gpt-4o`)

```powershell
az cognitiveservices account deployment create `
  --name thenameofyourinstance `
  --resource-group yourresourcegroup `
  --deployment-name gpt-4o `
  --model-name gpt-4o `
  --model-version "2024-11-20" `
  --model-format OpenAI `
  --sku-name "standard" `
  --scale-type Standard
```

Reference: [az cognitiveservices account deployment create](https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account/deployment?view=azure-cli-latest#az-cognitiveservices-account-deployment-create)

---

### 5. Deploy the Function App

This handles AI summarization and software name extraction.

[![Deploy Function App to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FSoftwareRiskReview%2Ffunctionapp_azuredeploy.json)

---

### 6. Deploy the Logic App

This orchestrates the workflow: email trigger → function calls → Security Copilot.

[![Deploy Logic App to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FSoftwareRiskReview%2Flogicapp_azuredeploy.json)

---

## Prerequisites

- Azure OpenAI resource with deployed `gpt-4o` model
- Function App environment variables configured:
  - `AZURE_OPENAI_API_VERSION`
  - `AZURE_OPENAI_DEPLOYMENT_NAME`
  - `AZURE_OPENAI_ENDPOINT`
  - `AZURE_OPENAI_KEY`
  - `AZURE_OPENAI_MODEL`
- Authorized Logic App connectors:
  - Office365 for shared mailbox access
  - Security Copilot for Promptbook invocation
- Promptbook deployed and Promptbook ID obtained

