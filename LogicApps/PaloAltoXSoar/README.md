# XSOAR + Security Copilot Integration

**Author:** Craig Freyman  
**Inspired by:** [Rick Kotlarz](https://github.com/RickKotlarz/Security-Copilot-Plugins-dev/tree/main/Palo_Alto_XSOAR)

This Logic App provides automated enrichment and threat analysis using Palo Alto XSOAR and Microsoft Security Copilot. It accepts an `incident_id` and `query`, which is then passed to the /public/v1/investigation/{incident_id} XSOAR endpoint. This API call acquires the raw enrichment data which is then passed to Security Copilot.  

Example output:
```text
### Security Copilot Analysis ###
**Assessment Summary:**  
No threat indicators detected — likely a false positive.

**Supporting Evidence:**  
- **ipinfo_v2**: The IP address 8.8.8.8 is associated with Google LLC, located in Mountain View, CA. It has a reputation score of 1, indicating it is a known and trusted IP. The IP is used for hosting and has no VPN, proxy, or TOR flags.
- **MISP V3**: No attributes found for the IP address 8.8.8.8, suggesting no known correlation or reports of malicious activity.
- **MISP V3**: No attributes found for the domain tvitter.com, and an error indicating the URL is not valid. This suggests a weak signal with no known correlation or reports.

The data from both tools indicate that the IP address 8.8.8.8 is benign, and the domain tvitter.com does not have any supporting evidence of being malicious. Therefore, this is likely a false positive.
```

## Overview

This solution is ideal for automating enrichment triage pipelines. It integrates:
- Palo Alto Cortex XSOAR API calls for retrieving investigation context
- Filtering and transformation of indicator data
- Submission of results to Security Copilot for AI-powered threat assessment
- Output formatting suitable for downstream reporting or analyst consumption

## Deployment

Click below to deploy the Logic App and required API connection to your Azure environment:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fsecuritycopilot%2Frefs%2Fheads%2Fmain%2FLogicApps%2FPaloAltoXSoar%2Fazure_deploy.json)  

## Post Deployment

Ensure you activate your Security Copilot connection by opening that block up and making sure there are no errors on the connection. You may have to reauthenticate that API connection.

### Required Parameters

| Parameter             | Description                                                |
|-----------------------|------------------------------------------------------------|
| `SubscriptionId`      | Azure Subscription ID where the resources will be deployed |
| `LogicAppName`        | Name for the deployed Logic App                            |
| `PaloAltoInstance`    | XSOAR instance base URL (e.g., `https://api-xyz.crtx.us...`) |
| `ApiKey`              | API key for XSOAR authorization header                     |
| `x-xdr-auth-id_value` | XSOAR Auth ID header value (default: `19`)                 |

## Workflow Summary

1. **Trigger:** HTTP POST with JSON payload containing `incident_id` and `query`
2. **Action:** Posts request to XSOAR using composed URI
3. **Parse:** Extracts and filters the JSON response
4. **Select:** Captures `brand` and `contents` fields for Security Copilot
5. **Evaluate:** Sends prompt to Security Copilot via Logic App connector
6. **Compose:** Assembles final analyst-ready output

## Example Trigger Payload

- Retrieve your HTTP endpoint by opening the HTTP action.  
- Use a test curl command like:

```bash
curl -X POST   -H 'Accept: application/json'   -H 'Content-Type: application/json'   -d '{"incident_id": 123456, "query": "${.}"}'   'https://prod-07.australiaeast.logic.azur......'
```

## Notes

- The deployed Logic App uses the `Securitycopilot` managed API connector. Ensure this connector is authorized post-deployment.
- Results are returned in plain-text analyst summaries from Security Copilot. Consider additional automation steps to email or store output.

## Security Considerations

- Ensure the API key for XSOAR is stored securely in Azure Key Vault or via ARM parameterization.
- Use managed identities and least-privilege principles for Logic App access.
- Regularly rotate secrets and monitor XSOAR API usage.

---
