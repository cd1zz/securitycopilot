# Security Copilot Phishing Analysis and Custom Solutions

## Overview

This repository provides a suite of tools, templates, and automation workflows to enhance email phishing detection, analysis, and response using Microsoft Security Copilot, Azure Logic Apps, and Function Apps. It is designed to streamline the deployment and integration of security automation solutions in Azure environments while allowing for customization based on specific organizational needs.

---

## Key Features

- **Phishing Email Analysis**: Automates phishing analysis with Security Copilot, integrating behavioral, contextual, and technical assessments.
- **Microsoft Sentinel Integration**: Updates incidents with detailed insights, comments, and analysis results.
- **Custom Plugins and APIs**: Extends functionality with tailored plugins for API and KQL interactions.
- **Sample Data for Testing**: Includes tools to generate synthetic attack traffic and test incident response workflows.

---

## Folder Structure

### **CustomPlugins**
- **Description**: Contains custom API and KQL plugins to extend Security Copilot and Azure capabilities.
- **Contents**:
  - API plugins for enhanced integrations.
  - KQL queries to enrich Azure Monitor and Sentinel functionalities.

### **FunctionApps**
- **Description**: Contains deployment templates, source code, and pre-packaged ZIP files for Azure Function Apps.
- **Contents**:
  - Templates to deploy Function Apps for email parsing, analysis, and data normalization.
  - Source code for custom Function App logic.

### **LogicApps**
- **Description**: Includes various Logic App templates and workflows for automation and integration.
- **Contents**:
  - Templates for different Logic App variants (e.g., shared mailbox monitoring, Sentinel updates).
  - Pre-configured workflows for phishing analysis and incident response.

### **SampleData**
- **Description**: Provides PowerShell scripts and sample data for testing and validating the solutions.
- **Contents**:
  - Scripts to generate synthetic attack traffic in Azure.
  - A sample incident response plan for security workflows.

---

## Getting Started

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/cd1zz/securitycopilot.git
   cd securitycopilot
   ```

2. **Explore Folders**:
   - **CustomPlugins**: Review custom integrations for extending functionality.
   - **FunctionApps**: Deploy Function Apps for email parsing and analysis.
   - **LogicApps**: Select and deploy the appropriate Logic App variant.
   - **SampleData**: Use the provided scripts to simulate attack scenarios for testing.

3. **Deploy**:
   - Follow the instructions in the respective folder's `README.md` or templates for deployment.
   - Use the provided "Deploy to Azure" buttons where available for simplified deployment.

4. **Test and Monitor**:
   - Use the sample data to validate the deployment.
   - Monitor workflows and review reports and incident updates in Microsoft Sentinel.

---

## Notes

- **Security Considerations**:
  - Review and secure resources like storage accounts, Function Apps, and Logic Apps with proper access controls.
  - Ensure compliance with corporate policies when processing sensitive email data.
- **Latest Releases**:
  - The `PhishingLA_Latest_Release` folder in **LogicApps** contains the most user-friendly and up-to-date Logic App version for deployment.

---

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests to improve this repository.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
