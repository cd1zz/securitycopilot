# User Submitted Phishing Analysis with Security Copilot

## Author
Craig Freyman

---

## Overview

This solution automates the analysis of user-submitted phishing emails using Security Copilot. It integrates seamlessly with Microsoft Office 365 and Microsoft Sentinel to provide real-time phishing detection and reporting. Designed for ease of deployment, this solution supports scenarios with or without Microsoft Defender for Office 365's Report Phishing capability.

---

### Key Features

- **Automated Phishing Analysis**: Processes user-submitted phishing emails in real-time, identifying behavioral and psychological traits of phishing attempts.
- **Office 365 Integration**: Monitors a shared mailbox to collect phishing email submissions.
- **HTML Report Generation**: Produces detailed, actionable HTML reports summarizing email analysis.
- **Sentinel/Defender Integration**: Updates Microsoft Sentinel incidents with comprehensive insights and adds comments to incidents when configured.
- **Flexible Identity Management**: Supports both system-managed and user-assigned managed identities for secure resource access.

---

## Deployment

The solution involves deploying two primary components:
1. **Function App**: Parses email content, extracts key details, and performs auxiliary processing.
2. **Logic App**: Orchestrates the workflow, integrates with API connections, and manages the overall phishing analysis process.

### Deployment Steps:
1. Deploy the **Function App**.
2. Deploy the **Logic App** variant of your choice.
3. Configure API connections, shared mailbox settings, and necessary integrations.
4. Enable the Logic App to start processing phishing email submissions.

---

## Solution Variants

### PhishingLA_Latest_Release
**Description**: This is the latest, most user-friendly, and easy-to-deploy version of the Logic App. It should be tightened per your company security policy, but is streamlined deployment and integration.
- **Key Features**:
  - Uses a shared mailbox as the trigger.
  - Leverages system-managed identity for secure access.
  - Integrates with Microsoft Sentinel for incident updates and reporting.
- **Output**: Sends HTML analysis reports and updates Sentinel incidents when configured.

### Other Variants
1. **PhishingLA_MDTI**:
   - **Description**: Uses Microsoft Defender Threat Intelligence (MDTI) for enhanced threat intelligence.
   - **Functionality**: Monitors a specified mailbox (not shared) and emails detailed analysis reports.
   - **Output**: Generates an emailed analysis report.

2. **PhishingLA_Sentinel_Comments_sysmng_identity**:
   - **Description**: Utilizes system-managed identity for authentication.
   - **Functionality**: Adds comments to Sentinel incidents and emails detailed reports.
   - **Output**: Updates Sentinel incidents with comments and sends reports.

3. **PhishingLA_Sentinel_Comments_usrmg_identity**:
   - **Description**: Utilizes user-assigned managed identity for authentication.
   - **Functionality**: Adds comments to Sentinel incidents and emails detailed reports.
   - **Output**: Updates Sentinel incidents with comments and sends reports.

4. **PhishingLA_SharedMailboxOnly**:
   - **Description**: Uses a shared mailbox as the trigger (as defined in Entra).
   - **Functionality**: Processes phishing emails and sends detailed reports.
   - **Output**: Generates an emailed analysis report.

---

## Getting Started

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/cd1zz/securitycopilot.git
   cd securitycopilot
   ```

2. **Choose a Variant**: Select the Logic App variant that best fits your requirements.

3. **Deploy**:
   - Use the provided **Deploy to Azure** buttons in the documentation to deploy the Function App and Logic App.
   - For the latest release, use the templates in the `PhishingLA_Latest_Release` folder.

4. **Configure**:
   - Set up the shared mailbox for email monitoring.
   - Enable API connections (Office 365, Security Copilot, Azure Monitor Logs, Sentinel).
   - Grant necessary permissions to managed identities.

5. **Enable the Workflow**: Once deployed, enable the Logic App to start monitoring and processing emails.

---

## Notes

- **PhishingLA_Latest_Release Folder**: This folder contains the most up-to-date and easy-to-deploy Logic App. It is designed to balance ease of use and security, simplifying deployment while ensuring compatibility with Azure best practices.
- **Security Considerations**:
  - Review access controls for all deployed resources, including Function Apps, storage accounts, and API connections.
  - Secure storage accounts with private endpoints and disable public access.
  - Regularly update Function App dependencies to mitigate security risks.
  - Ensure compliance with corporate security policies when processing sensitive email data.
- **Deployment vs. Security**: This solution prioritizes ease of deployment and integration. Review the setup to ensure it meets your organization's security requirements.

---

## Contributions

Contributions and suggestions are welcome! Open an issue or submit a pull request to enhance this solution.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.