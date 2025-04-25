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

You can only deploy specific OpenAI models if the region you choose supports them (e.g., GPT-4.1 requires East US 2 or Sweden Central as of now).

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

Creates a new Azure OpenAI resource, which is required before you can deploy and use models like gpt-4, gpt-4.1, or gpt-4o.

Parameter details:
  --name: Unique name of your Azure OpenAI resource.
  --resource-group: Azure Resource Group to contain this resource.
  --kind OpenAI: Specifies this is an Azure OpenAI resource (not a generic Cognitive Service).
  --sku S0: Standard pricing tier (S0 is the only available tier for OpenAI).
  --location: Region where this resource will be deployed (must be one that supports the model you want later).
  --custom-domain: Friendly DNS name prefix for the endpoint.
  --yes: Automatically confirms creation (bypasses interactive confirmation).

Reference: [az cognitiveservices account create](https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account?view=azure-cli-latest#az-cognitiveservices-account-create)

---

### 4. Deploy a Model (e.g., `gpt-4o`)

Creates a model deployment inside the previously created Azure OpenAI resource. This is what lets you call the model via API using a specific deployment-name.

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

What it does:
Creates a model deployment inside the previously created Azure OpenAI resource. This is what lets you call the model via API using a specific deployment-name.

Parameter details:
  --name: The same OpenAI resource name created above.
  --resource-group: The same resource group.
  --deployment-name: The name you assign to this deployment (used later in API calls, e.g., "gpt-4o").
  --model-name: The base model you're deploying (e.g., "gpt-4o", "gpt-4.1").
  --model-version: The specific version of the model (e.g., "2024-11-20").
  --model-format OpenAI: Specifies this is an OpenAI format model (standard for GPT family).

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

