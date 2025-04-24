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
- **`extract_regex`**: Regex-extracts software name.
- **`research_agent`**: Leverages DuckDuckGo and Azure OpenAI for summarization.

### Microsoft Security Copilot
- Runs a Promptbook using software details for risk review.

---

## Azure OpenAI Model Setup

This solution requires an Azure OpenAI resource with a deployed model. Follow these steps:

### 1. Create Azure OpenAI Resource
```bash
az cognitiveservices account create \
  --name your-openai-name \
  --resource-group your-rg \
  --kind OpenAI \
  --sku Standard \
  --location your-region \
  --custom-domain your-openai-name.openai.azure.com \
  --yes
```

### 2. Deploy a Model (e.g., `gpt-4o`)
Use Azure Portal or CLI:

```bash
az cognitiveservices account deployment create \
  --name your-openai-name \
  --resource-group your-rg \
  --deployment-name gpt-4o \
  --model-name gpt-4o \
  --model-version 2024-04-01 \
  --model-format OpenAI \
  --scale-type Standard
```

> The Function App expects the following model environment variables:
> - `AZURE_OPENAI_API_VERSION` (default: `2023-12-01-preview`)
> - `AZURE_OPENAI_DEPLOYMENT_NAME` (default: `gpt-4o`)
> - `AZURE_OPENAI_ENDPOINT` (e.g., `https://your-openai-name.openai.azure.com/`)
> - `AZURE_OPENAI_KEY` (from the resource's Keys blade)
> - `AZURE_OPENAI_MODEL` (default: `gpt-4o`)

---

## Email Input Format

Subject Example:
```
SoftwareRiskReview: Dovetail
```

---

## Deployment Instructions

### Deploy the Function App
```bash
az functionapp deployment source config-zip \
  --resource-group WebResearchAgentV3 \
  --name webaiagent123abc \
  --src ./WebResearchAgent.zip
```

### Deploy the Logic App
Import the JSON definition from this repo into the Azure Portal or deploy via Bicep/ARM.

---

## Prerequisites

- Azure OpenAI resource with deployed model
- Security Copilot Promptbook published
- Logic App connectors for Office365 and Security Copilot configured
- Azure Function App with `AZURE_OPENAI_*` variables set
