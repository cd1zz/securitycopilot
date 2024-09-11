# User Submitted Phishing Analysis with Copilot for Security
This solution demonstrates how Copilot for Security can be used to automate the analysis of user submitted phishing emails. The solution monitors a shared inbox for new emails. When emails are received, the Logic App triggers and begins processing. The process includes a Function App to parse the relevant parts of the email and passes those to VirusTotal and Copilot for Security.

## Notes
If you want to change the function app code you can git clone the repo. Every time you change the FunctionApp code, be sure to repackage the FunctionApp.zip file. The zip file is what is referenced when the solution is deployed. The local .python_packages folder is necessary when deploying in this "push to deploy" manner. 

## Deploy the Solution

### Step 1: Deploy the Function App

Click the button below to deploy the Function App. You will be prompted to select or create a resourceGroup, and provide a unique FunctionAppName. FunctionApp names must be unique to the world. Make sure the Function App deploymen is fully deployed before you initiate the Logic App deployment. 

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fcfsphishing_mdti%2Fmain%2Ffunctionapp_azuredeploy.json)

### Step 2: Deploy the Logic App

Click the button below to deploy the Logic App. Have your Function App name & resource group. You will enter this information in the deployment screen. 

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcd1zz%2Fcfsphishing_mdti%2Fmain%2Flogicapp_azuredeploy.json)


### Step 3: Initialize O365 and Security Copilot API connections

Open your new Logic App.

Click "API Connections"

![alt text](image.png)

Authorize both of the API connections.
![alt text](image-1.png)

### Step 4: Enable the Logic App
![alt text](image-3.png)
