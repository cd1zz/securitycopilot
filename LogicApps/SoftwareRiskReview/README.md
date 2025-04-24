# Software Risk Review Automation

This solution enables automated **Software Risk Reviews** by orchestrating an Azure Logic App, a Function App, and a Security Copilot Promptbook. It is designed to trigger from emails sent to a shared mailbox with a subject line that includes a software name, conduct automated web research, and produce an enterprise security assessment.

---

## Solution Overview

1. **Trigger**: Monitors a shared mailbox for new messages containing the keyword `SoftwareRiskReview:` in the subject line.  
2. **Extraction**: Extracts the software name using regex.  
3. **Web Research**: Uses Azure OpenAI to summarize web-sourced software intelligence.  
4. **Security Analysis**: Submits findings to a Security Copilot Promptbook for expert risk evaluation.

---

## Components

### Azure Logic App

- Triggers on email arrival in a shared mailbox.
- Extracts software name and initiates Function App calls.
- Posts collected insights to Security Copilot.

### Azure Function Apps

- `extract_regex`: Regex-extracts software name.
- `research_agent`: Leverages DuckDuckGo and Azure OpenAI for summarization.

### Microsoft Security Copilot

- Runs a Promptbook using software details for risk review.

---

## Azure OpenAI Model Setup

This solution requires an Azure OpenAI resource with a deployed model. Follow these steps:

### 1. Create Azure OpenAI Resource

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

Reference URL: [https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account?view=azure-cli-latest#az-cognitiveservices-account-create}]

### 2. Deploy a Model (e.g., `gpt-4o`)

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

Reference URL: [https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account/deployment?view=azure-cli-latest#az-cognitiveservices-account-deployment-create]

Environment variables expected by the Function App:

- `AZURE_OPENAI_API_VERSION` (default: `2023-12-01-preview`)
- `AZURE_OPENAI_DEPLOYMENT_NAME` (default: `gpt-4o`)
- `AZURE_OPENAI_ENDPOINT` (e.g., `https://your-openai-name.openai.azure.com/`)
- `AZURE_OPENAI_KEY` (from Azure OpenAI resource Keys)
- `AZURE_OPENAI_MODEL` (default: `gpt-4o`)

---

## Email Input Format

Subject line should follow the format:

```
SoftwareRiskReview: Dovetail
```

Only subject content is parsed. The mailbox should be monitored by the Logic App.

---

## Deployment Options

### Deploy the Function App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FSoftwareRiskReview%2Ffunctionapp_azuredeploy.json)

### Deploy the Logic App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FSoftwareRiskReview%2Ffunctionapp_azuredeploy.json)

---

## Prerequisites

- Azure OpenAI resource with a deployed model as outlined above.
- **Security Copilot Promptbook must be created in advance**. You will need the `PromptbookId` GUID at deployment time.
- Prompt definitions are located here:  
  [PromptBookPrompts.md](https://github.com/cd1zz/securitycopilot/blob/main/LogicApps/SoftwareRiskReview/PromptBookPrompts.md)
- Logic App connectors must be authorized for:
  - Office365
  - Security Copilot
- The Function App must be configured with all required `AZURE_OPENAI_*` environment variables.

