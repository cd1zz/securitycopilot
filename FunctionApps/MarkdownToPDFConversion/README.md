# Markdown to PDF Converter Function App

This Azure Function App accepts raw Markdown text via HTTP POST and returns a PDF file rendered from the content. It is designed for integration into Azure Logic Apps, but can be used without as well.

---

## Function Overview

**Function Name:** `convert_markdown_pdf`  
**Method:** `POST`  
**Route:** `/`  
**Input Content-Type:** `text/plain` or `application/json` (raw Markdown in body)  
**Output:** PDF file (returned as base64 in Logic App)

---

## Sample Markdown Input

```markdown
### Incident Report

#### Summary
| Key | Value |
|-----|-------|
| Time Created | 2025-03-11 20:14:37 |
| Affected User | michael@dundermiff.local |

#### Actions
1. Reset credentials
2. Investigate sign-in anomalies
```

---

## Logic App Integration Example

This example Logic App performs the following steps:

1. Calls Security Copilot to generate a Markdown incident report.
2. Sends the Markdown string to this function.
3. Uses the resulting base64 PDF output in an email attachment.

### Sample Action to Call Function App

```json
"Markdown_to_PDF_Conversion": {
  "type": "Function",
  "inputs": {
    "body": "@body('Submit_a_Security_Copilot_prompt')?['EvaluationResultContent']",
    "function": {
      "id": "/subscriptions/<sub-id>/resourceGroups/<rg-name>/providers/Microsoft.Web/sites/<function-app-name>/functions/convert_markdown_pdf"
    }
  }
}
```

---

## Using the PDF in Email (as Attachment)

After the `convert_markdown_pdf` function completes, extract the base64 PDF content using a Compose action:

```json
"Compose": {
  "inputs": "@body('Markdown_to_PDF_Conversion')?['$content']"
}
```

Then use the output in the email action:

```json
"Attachments": [
  {
    "Name": "incident_report.pdf",
    "ContentBytes": "@outputs('Compose')"
  }
]
```

---

## Response Schema

When called from a Logic App, the function returns:

```json
{
  "$content-type": "application/pdf",
  "$content": "<base64-pdf-blob>"
}
```

This is compatible with the `ContentBytes` field used in Logic App connectors such as Office 365 Outlook.

---

## Dependencies

The following Python packages are required in the Function App deployment:

```
azure-functions
markdown
weasyprint
```

These have been installed into the .python_packages folder which is part of the deployment ZIP file.  

---

## Deployment Instructions

1. Deploy using the Azure CLI:

```powershell
az functionapp deployment source config-zip \
  --resource-group markdowntopdfconversion \
  --name markdowntopdfconversion \
  --src .\MarkdownToPDFConversion.zip
```

**Note:** Ensure the Function App is created with Python 3.10+ and Linux OS for compatibility with WeasyPrint.

---
