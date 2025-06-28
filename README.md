 Gmail Link Extractor & Phishing Domain Detector

This Python script connects securely to your Gmail account, scans your most recent emails, extracts hyperlinks from the HTML content, and flags any links that lead to suspicious domains. The results are saved in a CSV report and automatically opened for easy review.

---

## 🧩 Features

-  OAuth 2.0 Authentication with Gmail API  
- Scans the 5 most recent emails
-  Extracts hyperlinks from email body  
-  Flags suspicious domains like URL shorteners  
-  Exports results to `email_link_report.csv`  
- Automatically opens the CSV report after scanning  
-  Clean code with helpful comments and logging  

example output:
🕒 Email Date: 2025-06-26 18:23:10
📧 Subject: Your Account Statement
📤 From: support@gmail.com
🔗 Links found in this email:

https://bit.ly/fake-login
⚠️ Suspicious domain detected: bit.ly
![image](https://github.com/user-attachments/assets/9c7fb6dd-c587-40b0-9c81-7fdfa68320ea)


Set up instructions
1) clone repo
2) install python depdencencies: pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib beautifulsoup4
3) enable Gmail API and get your credentials.json

gitignore
- to avoid uploading credentials, make sure this line exists in gitignore
credentials.json


Use Cases: 
- email forensics and pishing analysis
- cybersecuity awareness and training
- safe gmail link tarcking and monitoring
- automation or gmail based audit tools



Customization:
- you can change max_results= 5 to any number to scan more emails
- you can edit suspicious_domains to meet ur use case


Dependencies List
- google-api-python-client
- google-auth-httplib2
- google-auth-oauthlib
- beautifulsoup4
