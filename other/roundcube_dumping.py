import requests
from bs4 import BeautifulSoup
import os
import sys
import re
import argparse
from urllib.parse import quote
import json
import email
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMPLETED_FILE = "completed.txt"
PROGRESS_FILE = "progress.json"

def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_progress(progress):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, indent=2)

def login_to_roundcube(session, base_url, username, password):
    print(f"\n[+] Logging in as {username}")
    r = session.get(f"{base_url}/?_task=login")
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        raise Exception("[-] CSRF token not found on login page.")
    csrf_token = token_input.get("value", "")
    print(f"[+] CSRF token found: {csrf_token}")

    payload = {
        "_user": username,
        "_pass": password,
        "_action": "login",
        "_task": "login",
        "_token": csrf_token
    }

    response = session.post(f"{base_url}/?_task=login", data=payload)
    if "logout" not in response.text.lower():
        raise ValueError(f"[-] Login failed for user '{username}': invalid username or password.")
    print("[+] Login successful.")
    return response

def get_csrf_token(session, base_url):
    """Get CSRF token from the mail interface"""
    r = session.get(f"{base_url}/?_task=mail")
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    if token_input:
        return token_input.get("value", "")
    return ""

def is_email_recent_fast(email_content, days=7):
    """Quick date check on email content without full parsing"""
    try:
        # Look for Date header in the first few lines
        lines = email_content.decode('utf-8', errors='ignore').split('\n')[:20]
        date_line = None
        for line in lines:
            if line.lower().startswith('date:'):
                date_line = line
                break
        
        if not date_line:
            return True  # If no date found, include it to be safe
        
        date_str = date_line.split(':', 1)[1].strip()
        email_date = parsedate_to_datetime(date_str)
        if email_date.tzinfo is None:
            email_date = email_date.replace(tzinfo=datetime.now().astimezone().tzinfo)
        threshold = datetime.now(email_date.tzinfo) - timedelta(days=days)
        return email_date >= threshold
    except Exception:
        return True  # If parsing fails, include it to be safe

def list_emails_in_folder_with_date_filter(session, base_url, folder, days=7):
    """List all emails in folder and filter by date locally"""
    time_desc = "week" if days == 7 else f"{days} days"
    print(f"\n=== Processing folder: {folder} for emails from last {time_desc} ===")
    
    inbox_url = f"{base_url}/?_task=mail&_mbox={quote(folder)}"
    r = session.get(inbox_url)
    
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        print(f"[-] CSRF token not found for folder {folder}, skipping.")
        return []
    csrf_token = token_input.get("value", "")

    all_uids = []
    recent_uids = []
    page = 1
    seen_uids = set()
    
    print(f"[+] Fetching all emails from folder '{folder}' and filtering by date...")
    
    while True:
        print(f"[+] Fetching page {page} for folder '{folder}'...")
        
        # Building URL with parameters like the browser does
        params = {
            "_task": "mail",
            "_action": "list",
            "_refresh": "1",
            "_layout": "widescreen",
            "_mbox": folder,
            "_page": str(page),
            "_remote": "1",
            "_unlock": f"loading{int(datetime.now().timestamp() * 1000)}",
            "_": str(int(datetime.now().timestamp() * 1000))
        }
        
        # Building the URL manually to ensure proper formatting
        param_string = "&".join([f"{k}={v}" for k, v in params.items()])
        ajax_url = f"{base_url}/?{param_string}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate, br",
            "X-Roundcube-Request": csrf_token,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{base_url}/?_task=mail&_mbox={quote(folder)}",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin"
        }
        
        response = session.get(ajax_url, headers=headers)
        
        if response.status_code != 200:
            print(f"[-] Failed to fetch page {page} for folder '{folder}' (HTTP {response.status_code})")
            break
        
        # Extract UIDs from this page
        page_uids = re.findall(r'add_message_row\((\d+),', response.text)

        if not page_uids:
            if page == 1:
                print(f"[!] No emails found in folder '{folder}' - folder might be empty")
            else:
                print(f"[+] No emails found on page {page} - reached end")
            break
        
        # Check for duplicate UIDs
        new_uids = []
        duplicate_count = 0
        for uid in page_uids:
            if uid in seen_uids:
                duplicate_count += 1
            else:
                new_uids.append(uid)
                seen_uids.add(uid)
        
        if duplicate_count > 0:
            print(f"[!] Found {duplicate_count} duplicate UIDs on page {page}")
        
        if not new_uids:
            print(f"[+] All UIDs on page {page} are duplicates - reached end")
            break
        
        all_uids.extend(new_uids)
        print(f"[+] Found {len(new_uids)} new emails on page {page} (total so far: {len(all_uids)})")
        
        # Now filter these UIDs by date
        print(f"[+] Checking dates for {len(new_uids)} emails on page {page}...")
        page_recent_count = 0
        
        for uid in new_uids:
            # Quick check - fetch just the headers to check date
            url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"
            try:
                r = session.get(url)
                if r.status_code == 200 and r.content.strip():
                    if is_email_recent_fast(r.content, days):
                        recent_uids.append(uid)
                        page_recent_count += 1
            except Exception as e:
                print(f"[-] Error checking date for UID {uid}: {e}")
                # Include it anyway to be safe
                recent_uids.append(uid)
                page_recent_count += 1
        
        print(f"[+] Found {page_recent_count} recent emails on page {page} (total recent: {len(recent_uids)})")
        
        # Try to extract pagination info from the response
        try:
            rowcount_match = re.search(r'set_rowcount\("Messages (\d+) to (\d+) of (\d+)"', response.text)
            if rowcount_match:
                start_msg = int(rowcount_match.group(1))
                end_msg = int(rowcount_match.group(2))
                total_msg = int(rowcount_match.group(3))
                print(f"[+] Messages {start_msg} to {end_msg} of {total_msg}")
                
                if end_msg >= total_msg:
                    print(f"[+] Reached end of messages ({end_msg}/{total_msg})")
                    break
        except Exception:
            # Fallback: if we got fewer than 50 UIDs, assume we're done
            if len(page_uids) < 50:
                print(f"[+] Got {len(page_uids)} emails (< 50), assuming last page")
                break
        
        page += 1
        
        # Safety check to prevent infinite loops
        if page > 50:
            print(f"[!] Reached page limit (50), stopping pagination for folder '{folder}'")
            break
    
    if recent_uids:
        time_desc = "week" if days == 7 else f"last {days} days"
        print(f"[+] Found {len(recent_uids)} emails from the {time_desc} out of {len(all_uids)} total emails in folder '{folder}'")
    else:
        time_desc = "week" if days == 7 else f"last {days} days"
        print(f"[!] No emails found in folder '{folder}' for the {time_desc}")
        print(f"[i] This folder contains only emails older than {time_desc}")
    
    return recent_uids

def extract_folders_from_mail_env(response_text):
    # Try multiple patterns to find the rcmail.set_env block
    patterns = [
        r"rcmail\.set_env\((\{.*?\})\);",
        r"rcmail\.set_env\((\{.*?\})\)",
        r"this\.set_env\((\{.*?\})\);",
        r"this\.set_env\((\{.*?\})\)"
    ]
    
    env_dict = None
    for pattern in patterns:
        match = re.search(pattern, response_text, re.DOTALL)
        if match:
            env_js_obj = match.group(1)
            # Clean up the JavaScript object to make it valid JSON
            env_js_obj = re.sub(r"([{,])\s*([a-zA-Z0-9_]+)\s*:", r'\1 "\2":', env_js_obj)
            env_js_obj = env_js_obj.replace("'", '"')
            try:
                env_dict = json.loads(env_js_obj)
                break
            except Exception as e:
                print(f"[-] JSON parsing error with pattern {pattern}: {e}")
                continue
    
    if env_dict:
        mailboxes = env_dict.get("mailboxes_list") or list(env_dict.get("mailboxes", {}).keys())
        if mailboxes:
            print(f"[+] Found folders: {mailboxes}")
            return mailboxes
    
    # Fallback: look for folder names in the HTML
    print("[!] rcmail.set_env block not found, trying HTML parsing fallback...")
    
    folder_patterns = [
        r'_mbox=([^&"\']+)',
        r'data-id="([^"]+)"[^>]*class="[^"]*mailbox',
        r'class="[^"]*mailbox[^"]*"[^>]*data-id="([^"]+)"',
        r'<li[^>]*class="[^"]*mailbox[^"]*"[^>]*data-id="([^"]+)"',
        r'href="[^"]*_mbox=([^&"\']+)"'
    ]
    
    folders = set()
    for pattern in folder_patterns:
        matches = re.findall(pattern, response_text)
        for match in matches:
            folder = match.replace('%2E', '.').replace('%2F', '/').replace('%20', ' ')
            if folder and folder not in ['login', 'logout', 'mail', 'settings', 'addressbook']:
                folders.add(folder)
    
    if not folders:
        folders.add('INBOX')
    elif 'INBOX' not in folders:
        folders.add('INBOX')
    
    folder_list = list(folders)
    if folder_list:
        print(f"[+] Found folders via HTML parsing: {folder_list}")
        return folder_list
    
    print("[-] No folders found, defaulting to INBOX only")
    return ['INBOX']

def fetch_mail_folders(session, base_url):
    print("[+] Fetching mail folders...")
    r = session.get(f"{base_url}/?_task=mail")
    if "Roundcube Webmail Login" in r.text:
        print("[-] Still on login page, check credentials or session.")
        return []
    
    folders = extract_folders_from_mail_env(r.text)
    
    if folders:
        print(f"[+] Testing folder access...")
        test_folder = 'INBOX' if 'INBOX' in folders else folders[0]
        
        test_url = f"{base_url}/?_task=mail&_mbox={quote(test_folder)}"
        test_response = session.get(test_url)
        
        if test_response.status_code == 200:
            print(f"[+] Folder access verified with '{test_folder}'")
            print(f"[+] Will process all {len(folders)} folders: {folders}")
            return folders
        else:
            print(f"[-] Could not access folder '{test_folder}', but will try all folders anyway")
            return folders
    
    print("[-] No folders found, defaulting to INBOX only")
    return ['INBOX']

def save_email(session, base_url, folder, uid, output_dir):
    print(f"[+] Fetching UID {uid} from folder '{folder}'")
    url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"
    r = session.get(url)
    if r.status_code != 200 or not r.content.strip():
        print(f"[-] Failed to download UID {uid}")
        return

    os.makedirs(output_dir, exist_ok=True)

    eml_path = os.path.join(output_dir, f"{uid}.eml")
    with open(eml_path, "wb") as f:
        f.write(r.content)
    print(f"[✓] Saved email to: {eml_path}")

    try:
        msg = email.message_from_bytes(r.content, policy=policy.default)
        attachments_dir = os.path.join(output_dir, f"attachments_{uid}")
        os.makedirs(attachments_dir, exist_ok=True)

        attachment_found = False
        for part in msg.iter_parts():
            content_disposition = part.get_content_disposition()
            if content_disposition == "attachment" or (
                part.get_filename() and content_disposition in ["inline", None]
            ):
                filename = part.get_filename() or f"part-{uid}.bin"
                file_path = os.path.join(attachments_dir, filename)
                with open(file_path, "wb") as af:
                    af.write(part.get_payload(decode=True))
                print(f"[📎] Extracted attachment: {file_path}")
                attachment_found = True

        if not attachment_found:
            os.rmdir(attachments_dir)
    except Exception as e:
        print(f"[-] Error parsing attachments for UID {uid}: {e}")

def process_account(username, password, base_url, days, session, progress):
    output_base = f"./backup_{username}"
    os.makedirs(output_base, exist_ok=True)
    try:
        login_to_roundcube(session, base_url, username, password)
        folders = fetch_mail_folders(session, base_url)
        user_progress = progress.get(username, {})

        for folder in folders:
            try:
                print(f"\n{'='*60}")
                print(f"Processing folder: {folder}")
                print(f"{'='*60}")
                
                # Use regular list with local date filtering
                uids = list_emails_in_folder_with_date_filter(session, base_url, folder, days)
                
                if not uids:
                    time_desc = "week" if days == 7 else f"last {days} days"
                    print(f"[!] No emails found in folder '{folder}' for the {time_desc}, skipping...")
                    continue
                
                folder_dir = os.path.join(output_base, folder.replace('/', '_'))
                os.makedirs(folder_dir, exist_ok=True)

                last_uid = user_progress.get(folder)
                start_index = 0
                if last_uid and last_uid in uids:
                    start_index = uids.index(last_uid) + 1
                    print(f"[↪] Resuming from UID {last_uid} in folder '{folder}' for user {username}")
                
                processed_count = 0
                for uid in uids[start_index:]:
                    save_email(session, base_url, folder, uid, folder_dir)
                    processed_count += 1
                    user_progress[folder] = uid
                    progress[username] = user_progress
                    save_progress(progress)
                
                time_desc = "week" if days == 7 else f"last {days} days"
                print(f"[✓] Processed {processed_count} emails from the {time_desc} in folder '{folder}'")
                
            except Exception as e:
                print(f"[-] Error processing folder '{folder}': {e}")
                print(f"[!] Continuing with next folder...")
                continue
            finally:
                progress[username] = user_progress
                save_progress(progress)

        print(f"\n[✓] Backup complete for {username}. Emails saved in '{output_base}'")
        print("-----------------------------------------------------------------------------------------------------")
        with open(COMPLETED_FILE, "a") as f:
            f.write(username + "\n")
        
        if username in progress:
            del progress[username]
            save_progress(progress)
    except Exception as e:
        print(f"[-] Error processing {username}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Roundcube Email Backup Tool (Optimized with Local Date Filtering)",
        usage=(
            "python %(prog)s -u <username> -p <password> [--days <N>] [--url <base_url>]\n"
            "       %(prog)s -f <file_with_username_colon_password> [--days <N>] [--url <base_url>]"
        )
    )

    parser.add_argument("-u", "--username", help="Username for login")
    parser.add_argument("-p", "--password", help="Password for login")
    parser.add_argument("-f", "--file", help="File with username:password per line")
    parser.add_argument("--url", default="http://127.0.0.1:9876", help="Base URL to Roundcube (default: http://127.0.0.1:9876)")
    parser.add_argument("--days", type=int, default=7, help="Filter emails newer than N days (default: 7 - one week)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    base_url = args.url.rstrip("/")
    if not base_url.startswith("http"):
        print("[-] Please include 'http://' or 'https://' in the --url.")
        sys.exit(1)

    accounts = []
    if args.file:
        if not os.path.isfile(args.file):
            print("[-] Provided file does not exist.")
            sys.exit(1)
        with open(args.file, "r") as f:
            for line in f:
                if ":" in line:
                    user, pwd = line.strip().split(":", 1)
                    accounts.append((user, pwd))
    elif args.username and args.password:
        accounts.append((args.username, args.password))
    else:
        print("[-] You must provide -u/-p or -f <file>")
        parser.print_help()
        sys.exit(1)
    
    completed_users = set()
    if os.path.exists(COMPLETED_FILE):
        with open(COMPLETED_FILE, "r") as f:
            completed_users = set(line.strip() for line in f if line.strip())
    
    progress = load_progress()

    for username, password in accounts:
        
        if username in completed_users:
            print(f"[✓] Skipping already completed user: {username}")
            continue
        
        session = requests.Session()
        session.verify = False
        try:
            process_account(username, password, base_url, args.days, session, progress)
        except Exception as e:
            print(f"[-] Error processing account {username}: {e}")

if __name__ == "__main__":
    main()