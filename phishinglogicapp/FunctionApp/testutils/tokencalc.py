import tiktoken

# List of GPT-4 model options
models = ["gpt-4", "gpt-4-32k"]

# Your text
text = "/AskGpt\n\n### Task: Conduct a detailed analysis of the email body to assess for phishing intent, focusing on the email's intent and any actions it encourages. Break down your analysis step-by-step, emphasizing any suspicious requests or manipulative tactics that could suggest phishing. Be mindful of legitimate transactional emails from known companies, especially where legitimate and suspicious elements may overlap.\n\nEmail Body:\n\"\"\"\n\nValued Customer,Please find attached your Virtual Door Hanger -- a summary of service from our recent trip. The attached is not an invoice, as a service invoice will be forthcoming.We appreciate your business!MCPS, Inc\n\"\"\"\nSender and Subject Information:\n\"\"\"\nSender: \"Virtual Door Hanger (VirtualDoorHanger@mcpsvail.com)\" <system@sent-via.netsuite.com>\nReply-To: Virtual Door Hanger <messages.6982390.6356740.b92aa72699@6982390.email.netsuite.com>\nSubject: MCPS Virtual Door Hanger ST106245\n\"\"\"\n\n### Analysis Steps:\n\n1. **Intent and Action Encouraged**: Determine the email's primary intent. Is it prompting the recipient to take an action (e.g., click a link, download an attachment, or provide information)? If an action is requested, assess whether it’s consistent with expected interactions from a legitimate sender.\n\n2. **Sender Analysis**: Review the sender’s email address and domain for authenticity. Confirm if the domain matches the expected sender and evaluate whether it resembles known and trusted contacts or companies. Consider common tactics like domain impersonation or subtle misspellings.\n\n3. **Psychological Tactics**:\n   - Identify if the email uses urgency, fear, or other manipulative tactics to encourage action. For well-known brands, recognize that some urgency (e.g., shipping notifications) may be legitimate.\n   - Differentiate legitimate service-related urgency from manipulative tactics by assessing if the urgency aligns with the company’s usual communication style.\n\n4. **Requests for Sensitive Information**: Examine the content for direct or indirect requests for sensitive data, such as credentials, financial information, or personal identifiers. Legitimate transactional emails generally avoid unnecessary sensitive requests.\n\n5. **Link and Attachment Inspection**:\n   - Carefully evaluate URLs, domains, and attachments in the email. For known brands, identify if tracking links (e.g., `click.e.usa.experian.com`) or subdomains align with the sender’s typical patterns.\n   - Ensure that links and attachments match the sender’s domain or established tracking subdomains, and avoid flagging tracking links that adhere to known known patterns.\n\n6. **Consistency with Legitimate Brand Communication**: Assess if the email’s language, branding, and structure are consistent with the expected brand identity. While professional emails should be well-structured, legitimate transactional emails from known companies may vary in formatting based on system-generated content.\n\n### Additional Guidance for Known Brands:\n- **Tracking Links**: For recognized brands, identify if URLs are structured as common tracking links. Treat these as neutral if they follow expected patterns.\n- **Routine Service Notifications**: If the email's urgency or request aligns with typical service notifications (e.g., order shipment confirmations), do not classify it as suspicious based solely on urgency.\n\n### Output Format:\n- **Summary**: Provide a concise overview of the email's intent, based on the actions it encourages and other indicators.\n- **Detected Indicators**:\n  - **PhishingIndicators**: Only list indicators of phishing here, focusing on suspicious requests, inconsistent branding, manipulative tactics, or unusual links/attachments.\n  - **PositiveIndicators**: (Optional) List positive or neutral traits here, such as verified sender address, tracking links matching known patterns, or routine service notifications.\n- **Assessment**: Conclude with one of the following: 'Benign,' 'Suspicious,' or 'Phishing.'\n\n### Example:\nDetected Indicators:\n1. **PhishingIndicators**: None detected.\n2. **PositiveIndicators**: \n   - Verified sender domain.\n   - Routine service-related urgency.\n   - Legitimate tracking link structure.\n\nAssessment: Benign\n"

# Iterate through models and calculate token counts
for model in models:
    # Get the encoding for the model
    encoding = tiktoken.encoding_for_model(model)
    
    # Encode the text
    tokens = encoding.encode(text)
    
    # Token count
    print(f"Model: {model} | Number of tokens: {len(tokens)}")


# Encode the text
tokens = encoding.encode(text)

# Token count
print(f"Number of tokens: {len(tokens)}")
