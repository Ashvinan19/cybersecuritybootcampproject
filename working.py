from googleapiclient.discovery import build # Google API client library
from google_auth_oauthlib.flow import InstalledAppFlow #handles OAuth 2.0 authentication
import base64 # used for decoding email content 
from bs4 import BeautifulSoup #helps extract and parse HTML content


from urllib.parse import urlparse # used to parse URLs
import datetime # used to get current date and time
import csv # used for saving results to CSV
import os # used for file operations
# Set Gmail read-only scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
# you can read users gmails messages, but you cannot send,delete, or modify them

# Authenticate and connect to Gmail API
def authenticate_gmail():
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES) #sets up flow for authentication with required scoped
    creds = flow.run_local_server(port=0)  # use run_console() if localhost gives error
    service = build('gmail', 'v1', credentials=creds)
    return service

# Extract URLs from the latest N emails
def extract_urls(service, max_results=5): #defines a function that takes in authentical gmail service, and fetches 5 latest emaisl
    result = service.users().messages().list(userId='me', maxResults=max_results).execute() # retrieves the latest N emails
    messages = result.get('messages', []) #gets list of message objects (IDs)

    suspicious_domains = ["bit.ly", "tinyurl.com", "click.example.com"]  # list of suspicious domains

    # ✅ Prepare CSV file
    with open("email_link_report.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Email Date", "Subject", "From", "URL", "Suspicious?"])

        # fetch full message ID using .get() 
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()

            #get readable timestamp from email
            timestamp = int(msg_data['internalDate']) / 1000  # convert to seconds
            email_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n🕒 Email Date: {email_time}")
            
            # get email subject
            headers = msg_data.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
            print(f"📧 Subject: {subject}")

            # get sender email
            sender = next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown Sender)')
            print(f"📤 From: {sender}")
            
            payload = msg_data.get('payload', {})
            parts = payload.get('parts', [])
            all_urls = [] #store all extracted links

            # checks if part of message is html 
            for part in parts:
                if part.get('mimeType') == 'text/html':
                    body_data = part['body'].get('data')
                    if body_data:
                        decoded_data = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                        soup = BeautifulSoup(decoded_data, 'html.parser')
                        links = [a['href'] for a in soup.find_all('a', href=True)]
                        all_urls.extend(links)

            unique_urls = list(set(all_urls)) #avoid duplicate links

            if unique_urls:
                print("🔗 Links found in this email:")
                for url in unique_urls:
                    domain = urlparse(url).netloc # get domain of url
                    print(f" - {url}")
                    suspicious_flag = "⚠️ Yes" if domain in suspicious_domains else "No"
                    if suspicious_flag == "⚠️ Yes":
                        print(f"   ⚠️ Suspicious domain detected: {domain}")
                    # ✅ Write to CSV
                    writer.writerow([email_time, subject, sender, url, suspicious_flag])
            else:
                print("🚫 No links found in this email.")
                # ✅ Write "no links" entry to CSV
                writer.writerow([email_time, subject, sender, "(No links)", "N/A"])

        # ✅ Notify user and attempt to open file automatically
        print("\n✅ All email data has been saved to 'email_link_report.csv'")

        try:
            if os.name == 'nt':  # Windows
                os.startfile("email_link_report.csv")
            elif os.name == 'posix':  # macOS or Linux
                os.system("open email_link_report.csv" if os.uname().sysname == "Darwin" else "xdg-open email_link_report.csv")
        except Exception as e:
            print(f"⚠️ Could not open the file automatically: {e}")




# Main script authenticates with Gmail and calls extract_urls to get links from emails
# Also prints each URL found
if __name__ == '__main__':
    service = authenticate_gmail()
    print("✅ Gmail API authentication successful!")

    extract_urls(service) #gets 5 lastest gmails emails and prints info per email
