# Security Copilot – ServiceNow Vulnerability Plugin

This plugin enables **Microsoft Security Copilot** to query **ServiceNow Vulnerability Response** and **Software Asset Management** data. It leverages an **Azure Function App** that abstracts the complexity of ServiceNow’s API calls and integrates directly with Security Copilot through a **custom plugin manifest**.

⚠️ **Important Note**: This integration has been tested **only with ServiceNOW environments using the Qualys integration**. Other scanner integrations (Tenable, Rapid7, etc.) may work through ServiceNow but are not supported or validated in this release.

---

## 🎯 Capabilities

* **Vulnerability Assessment**

  * Query ServiceNow by CVE ID or Qualys QID
  * Return affected system counts and representative samples
  * Generate deep links into ServiceNow for remediation workflows
  * Batch analyze multiple CVEs/QIDs

* **Software Inventory**

  * Query installed software by vendor or product name
  * Support wildcard searches (e.g. `Windows*`, `*Office`)
  * Return counts, sample systems, and version breakdowns

* **Optimized API**

  * Smart sampling for performance
  * Batch processing
  * Abstraction of ServiceNow API calls into simple endpoints

---

## 👥 Audience

* **Security Copilot Users**

  * Use natural language prompts in Copilot (e.g., *“Use the ServiceNOW vulnerability analyzer to check CVE-2024-1234”*).
  * Get system counts, affected host samples, and direct ServiceNow links.

* **Plugin Administrators**

  * Deploy the Azure Function App that serves the API
  * Upload the plugin manifest to Security Copilot
  * Manage ServiceNow credentials, keys, and permissions

---

## ⚙️ Architecture

```
Security Copilot ── Plugin Manifest ──► OpenAPI Spec ──► Azure Function App ──► ServiceNow API ──► Qualys data
```

---

## 🚀 Deployment Guide (Admins)

### 1. Prerequisites

* Azure subscription with permission to deploy Function Apps
* ServiceNow instance with:

  * **Vulnerability Response** module
  * **Software Asset Management** module
  * **Qualys integration** configured and ingesting vulnerabilities
* ServiceNow OAuth credentials with required roles:

  * Vulnerability: `sn_vul_read` or `sn_vul_admin`
  * Software inventory: `sam_user` or `asset`
  * CMDB read access

### 2. Deploy Function App

1. Clone the repo or obtain the Function App source package from [https://github.com/cd1zz/servicenow-security-copilot](https://github.com/cd1zz/servicenow-security-copilot)
2. Create a new Function App in Azure (Python 3.8–3.11)
3. Configure environment settings (`local.settings.json` for local dev, or App Settings in Azure)
4. Deploy to Azure:

   ```bash
   func azure functionapp publish <your-funcapp-name>
   ```
5. Verify deployment with a local `curl`:

   ```bash
   curl -X POST "https://<your-funcapp>.azurewebsites.net/api/analyze-vulnerability" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: your-api-key" \
     -d '{"vuln_id": "CVE-2024-1234"}'
   ```

---

## 🔌 Plugin Setup (Admins)


---

## 🌍 ServiceNOW Environment Variables

The Function App requires specific environment variables to connect securely to ServiceNOW and authenticate API calls.

```json
"Values": {
  "SERVICENOW_INSTANCE_URL": "https://your-instance.service-now.com",
  "SERVICENOW_CLIENT_ID": "your-client-id",
  "SERVICENOW_CLIENT_SECRET": "your-client-secret",
  "SERVICENOW_USERNAME": "your-username",
  "SERVICENOW_PASSWORD": "your-password",
  "API_KEY": "your-api-key"
}
```

### Variable Reference

* **`SERVICENOW_INSTANCE_URL`**
  The base URL of your ServiceNOW instance.
  Example: `https://example.service-now.com`

* **`SERVICENOW_CLIENT_ID`**
  OAuth Client ID generated when you create an application registry in ServiceNOW.

* **`SERVICENOW_CLIENT_SECRET`**
  OAuth Client Secret paired with the Client ID. Handle securely (e.g., Key Vault).

* **`SERVICENOW_USERNAME`**
  ServiceNOW username used for authentication. This account must have appropriate roles (`sn_vul_read`, `sam_user`, etc.).

* **`SERVICENOW_PASSWORD`**
  Password for the ServiceNOW username.

* **`API_KEY`**
  A **randomly generated, long, unique value** that acts as an authentication key for the Function App itself.

  * This is **not provided by ServiceNOW** — it must be created by the administrator.
  * All API requests from Security Copilot to the Function App must include this value in the `X-API-Key` header.
  * Recommended format: 32+ characters, alphanumeric with symbols.
  * Example generation in PowerShell:

    ```powershell
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
    -join ((1..64) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })

    ```

⚠️ **Security Tip**: Store all secrets (`CLIENT_SECRET`, `PASSWORD`, `API_KEY`) in **Azure Key Vault** or equivalent secure storage.

---

## 💻 Usage (Analysts)

Examples of natural language prompts once the plugin is active:

* **Single Vulnerability**

  ```
  Use the ServiceNOW vulnerability analyzer to show me all systems vulnerable to CVE-2024-1234
  ```
* **Qualys ID**

  ```
  Use the ServiceNOW vulnerability analyzer to analyze QID-92307
  ```
* **Batch**

  ```
  Use the ServiceNOW batch analyzer to check CVE-2025-55225 and CVE-2017-6168
  ```
* **Software Inventory**

  ```
  Use the ServiceNOW vulnerability analyzer to list all systems with Windows Server 2019 installed
  ```


---

## 📖 Prompting Effectively (Cost & Control)

| Prompt Style                                | Example                                                                                                                                                   | Cost    | Pros                                 | Cons                               |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------------------------------------ | ---------------------------------- |
| **Natural Language + Orchestrator**         | `Use the ServiceNOW vulnerability analyzer and tell me if we have any systems vulnerable to CVE-2025-55225 and include any servicenow_urls for reference` | Highest | Flexible, natural                    | Most tokens consumed               |
| **Semi-Explicit (Orchestrator + API hint)** | `/analyzeVulnerability CVE-2025-55225 and include servicenow_urls using the ServiceNOW vulnerability analyzer`                                            | Medium  | Faster plugin routing, extra context | Costs \~2× more than direct        |
| **Direct Skill Invocation**                 | `/analyzeVulnerability CVE-2025-55225`                                                                                                                    | Lowest  | Fastest, cheapest                    | Requires knowledge of skill syntax |

---

## 🍳 Prompt Cookbook

### Vulnerability Analysis

* Natural Language:

  ```
  Use the ServiceNOW vulnerability analyzer to check if we have any systems vulnerable to CVE-2025-55225 and include servicenow_urls
  ```
* Direct Skill:

  ```
  /analyzeVulnerability CVE-2025-55225
  ```

### Batch Vulnerability Check

* Natural Language:

  ```
  Use the ServiceNOW vulnerability analyzer to show me which systems are affected by CVE-2023-44487 and CVE-2025-55225
  ```
* Direct Skill:

  ```
  /batchAnalyze ["CVE-2023-44487", "CVE-2025-55225"]
  ```

### Software Inventory

* Natural Language:

  ```
  Use the ServiceNOW vulnerability analyzer to list all hosts with Microsoft Office installed and include version details
  ```
* Direct Skill:

  ```
  /softwareInventory {"software": "Office*"}
  ```

### Qualys ID Lookups

* Natural Language:

  ```
  Use the ServiceNOW vulnerability analyzer to check how many systems are vulnerable to Qualys ID 92307
  ```
* Direct Skill:

  ```
  /analyzeVulnerability QID-92307
  ```

### Status Search

* Direct Skill:

  ```
  /statusSearch {"confirmation_state": "confirmed"}
  ```

---

## 🔒 Security Considerations

* Store credentials in **Azure Key Vault**
* Use API key authentication for all Function App requests
* Apply **least privilege** to ServiceNow roles
* Never commit secrets into source control

---

## 🛠 Troubleshooting

* **Getting 0 systems returned?**

  * ServiceNow “state” values differ per instance. Try adjusting filters (e.g., `state!=3`).
* **Auth failures?**

  * Validate ServiceNow OAuth client ID/secret
  * Check Function App logs
* **Copilot not calling API?**

  * Verify manifest points to correct Function App base URL
  * Confirm Function App is publicly reachable

---

## 📚 References

* [ServiceNow API Documentation](https://developer.servicenow.com/)
* [Azure Functions Documentation](https://learn.microsoft.com/azure/azure-functions/)
* [Security Copilot Plugin API](https://learn.microsoft.com/en-us/copilot/security/plugin-api)
* Internal files:

  * `securitycopilot_servicenow_manifest_plugin.yaml` (plugin manifest)
  * `securitycopilot_servicenow_openapispec.yaml` (OpenAPI spec)

---

## 📝 License

MIT – see repository license file.
