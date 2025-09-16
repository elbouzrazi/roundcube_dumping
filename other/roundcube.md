![[Pasted image 20250801113049.png]]


```python
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

  

def is_email_recent(session, base_url, folder, uid, days=15):

    url = f"{base_url}/?_task=mail&_action=viewsource&_mbox={quote(folder)}&_uid={uid}"

    r = session.get(url)

    if r.status_code != 200 or not r.content.strip():

        print(f"[-] Failed to fetch UID {uid} from folder '{folder}'")

        return False

  

    try:

        headers = BytesParser().parsebytes(r.content, headersonly=True)

        date_str = headers.get("Date")

        if not date_str:

            print(f"[-] No Date header for UID {uid}")

            return False

        email_date = parsedate_to_datetime(date_str)

        if email_date.tzinfo is None:

            email_date = email_date.replace(tzinfo=datetime.now().astimezone().tzinfo)

        threshold = datetime.now(email_date.tzinfo) - timedelta(days=days)

        return email_date >= threshold

    except Exception as e:

        print(f"[-] Error parsing UID {uid} date: {e}")

        return False

  

def extract_folders_from_mail_env(response_text):

    match = re.search(r"rcmail\.set_env\((\{.*?\})\);", response_text, re.DOTALL)

    if not match:

        print("[-] rcmail.set_env block not found.")

        return []

  

    env_js_obj = match.group(1)

    env_js_obj = re.sub(r"([{,])\s*([a-zA-Z0-9_]+)\s*:", r'\1 "\2":', env_js_obj)

    env_js_obj = env_js_obj.replace("'", '"')

    try:

        env_dict = json.loads(env_js_obj)

        mailboxes = env_dict.get("mailboxes_list") or list(env_dict.get("mailboxes", {}).keys())

        print(f"[+] Found folders: {mailboxes}")

        return mailboxes

    except Exception as e:

        print(f"[-] JSON parsing error: {e}")

        return []

  

def fetch_mail_folders(session, base_url):

    print("[+] Fetching mail folders...")

    r = session.get(f"{base_url}/?_task=mail")

    if "Roundcube Webmail Login" in r.text:

        print("[-] Still on login page, check credentials or session.")

        return []

    return extract_folders_from_mail_env(r.text)

  

def list_emails_in_folder(session, base_url, folder):

    print(f"\n=== Processing folder: {folder} ===")

    inbox_url = f"{base_url}/?_task=mail&_mbox={quote(folder)}"

    r = session.get(inbox_url)

    soup = BeautifulSoup(r.text, "html.parser")

    token_input = soup.find("input", {"name": "_token"})

    if not token_input:

        print(f"[-] CSRF token not found for folder {folder}, skipping.")

        return []

    csrf_token = token_input.get("value", "")

  

    ajax_url = f"{base_url}/?_task=mail&_action=list"

    headers = {

        "X-Requested-With": "XMLHttpRequest",

        "Referer": inbox_url,

        "Content-Type": "application/x-www-form-urlencoded",

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

    uids = re.findall(r'add_message_row\((\d+),', response.text)

    print(f"[+] Folder '{folder}' has {len(uids)} emails.")

    return uids

  

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

    print(f"[✔] Saved email to: {eml_path}")

  

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

                uids = list_emails_in_folder(session, base_url, folder)

                folder_dir = os.path.join(output_base, folder)

                os.makedirs(folder_dir, exist_ok=True)

  

                last_uid = user_progress.get(folder)

                start_index = 0

                if last_uid and last_uid in uids:

                    start_index = uids.index(last_uid) + 1

                    print(f"[↪] Resuming from UID {last_uid} in folder '{folder}' for user {username}")

                for uid in uids[start_index:]:

                    if is_email_recent(session, base_url, folder, uid, days):

                        save_email(session, base_url, folder, uid, folder_dir)

                        user_progress[folder] = uid

                        progress[username] = user_progress

                        save_progress(progress)

            finally:

                progress[username] = user_progress

                save_progress(progress)

  

        print(f"\n[✓] Backup complete for {username}. Emails saved in '{output_base}'")

        with open(COMPLETED_FILE, "a") as f:

            f.write(username + "\n")

        if username in progress:

            del progress[username]

            save_progress(progress)

    except Exception as e:

        print(f"[-] Error processing {username}: {e}")

  

def main():

    parser = argparse.ArgumentParser(

        description="Roundcube Email Backup Tool",

        usage=(

            "python %(prog)s -u <username> -p <password> [--days <N>] [--url <base_url>]\n"

            "       %(prog)s -f <file_with_username_colon_password> [--days <N>] [--url <base_url>]"

        )

    )

  

    parser.add_argument("-u", "--username", help="Username for login")

    parser.add_argument("-p", "--password", help="Password for login")

    parser.add_argument("-f", "--file", help="File with username:password per line")

    parser.add_argument("--url", default="http://127.0.0.1:9876", help="Base URL to Roundcube (default: http://127.0.0.1:9876)")

    parser.add_argument("--days", type=int, default=15, help="Filter emails newer than N days")

  

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
```


















# 📄 Rapport Général sur la Gestion des Sessions dans Roundcube

**Auteur** : [Votre Nom]  
**Date** : 24 juillet 2025  
**Environnement** : Roundcube Webmail (Docker) avec MariaDB, Dovecot, Postfix

---

## 🌟 Objectif

Analyser le comportement du système de sessions de Roundcube lors de l'utilisation simultanée de plusieurs comptes utilisateurs, vérifier s'il y a des problèmes d'écrasement ou de gestion erronée des sessions, et valider la stabilité du système.

---

## 🛠️ Création et Simulation

- ✅ Création de **100 utilisateurs** système (`user1` à `user100`) avec le mot de passe `zaki`.
    
- ✅ Initialisation de leur boîte mail locale dans `/var/mail/`.
    
- ✅ Connexion simultanée via un script `bash + curl` simulant 100 connexions Roundcube en parallèle.
    

```bash
for i in $(seq 1 100); do
    useradd -m "user$i"
    echo "user$i:zaki" | chpasswd
    touch "/var/mail/user$i"
    chown "user$i":mail "/var/mail/user$i"
done
```

---

## 📝 Comportement des Sessions dans Roundcube

### ✅ Emplacement de Stockage des Sessions

- Les données de session sont stockées dans la table `session` de la base de données MariaDB.
    
- Chaque ligne correspond à une **session PHP unique**, pas à un utilisateur.
    

### ✅ Structure de la Table `session`

- `sess_id` : identifiant unique de session (cookie `PHPSESSID`)
    
- `changed` : horodatage de la dernière activité
    
- `ip` : adresse IP du client
    
- `vars` : données de session encodées en Base64 (utilisateur, interface, etc.)
    

---

## 🧪 Tests Effectués

### 1. Connexion avec un utilisateur

- Création d'une nouvelle ligne dans la table `session`.
    
- La colonne `vars` contient des données utilisateur : nom, IMAP, interface, etc.
    

### 2. Déconnexion

- La ligne de session reste dans la table.
    
- Les données sensibles dans `vars` sont effacées.
    
- Le champ `changed` est mis à jour.
    

### 3. Connexion avec un autre utilisateur après déconnexion (même navigateur)

- Une **nouvelle session** est créée avec un **nouvel ID**.
    
- La session précédente est écrasée (toutes les colonnes sont mises à jour).
    

### 4. Connexion avec un autre utilisateur après déconnexion (autre navigateur)

- Une nouvelle ligne de session est ajoutée.
    
- L'ancienne session est conservée (pas réutilisée).
    

### 5. Connexion avec un autre utilisateur sans déconnexion

- Une deuxième session apparaît dans la table (nouveau `sess_id`).
    
- Roundcube permet plusieurs sessions actives tant qu'on ne se déconnecte pas.
    

---

## 🤖 Observation finale (test avec 100 utilisateurs)

Après avoir exécuté le script de connexion, on observe la table `session` :

```sql
SELECT COUNT(*) FROM session;
```

**Résultat :** 100 lignes. Chaque utilisateur a généré une session propre, sans conflit ni erreur.

---

## 🔎 Analyse étendue : Pourquoi une seule session par navigateur ?

Roundcube (comme toute application PHP) utilise le cookie `PHPSESSID` pour gérer les sessions. Or, un navigateur ne peut stocker **qu'un seul cookie par domaine** → donc une seule session active à la fois.

**Conséquences :**

- Si on se connecte avec un autre utilisateur dans le même navigateur, l'ancien est déconnecté.
    
- Si on utilise un **navigateur différent**, **mode incognito**, ou un **profil séparé**, on peut avoir plusieurs sessions actives.
    

---

## 🔹 Résumé des Comportements Observés

|Comportement|Résultat|
|---|---|
|Connexion crée une session|✅ Oui|
|Déconnexion supprime la session|❌ Non, mais vide les données|
|Déconnexion nettoie les données|✅ Oui (colonne `vars` allégée)|
|Reconnexion avec même navigateur|❌ Non, une nouvelle session est créée|
|Connexion autre utilisateur sans logout|✅ Oui, une nouvelle ligne est créée|
|1 seule session visible si logout effectué|✅ Oui pour même navigateur, ❌ Non pour navigateurs différents (ancienne session conservée)|

---

## 📅 Conclusion

Roundcube gère correctement les connexions simultanées pour 100 utilisateurs. Aucun problème de session n'a été détecté. Chaque utilisateur dispose d'une session propre, isolée, et correctement stockée.

**Aucune altération ni conflit n'a été observé dans la table `session`.**

> Il est recommandé de mettre en place un script de nettoyage des sessions inactives pour éviter leur accumulation.


![[Pasted image 20250725122240.png]]


![[Pasted image 20250725120012.png]]
![[Pasted image 20250725120128.png]]
![[Pasted image 20250725121605.png]]
![[rouncube_session.png]]
![[Pasted image 20250725121725.png]]

![[Pasted image 20250725123648.png]]






### cronjob
```sql 
DELETE FROM session WHERE changed < (UNIX_TIMESTAMP() - 1800);

```

![[Pasted image 20250724140033.png]]

### decoded session
```r
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:9:"roundcube";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"C9w+NAUrH8Blm45/Iy0SiJc9lc79x7MQ";login_time|i:1753267825;STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"Ej5IahaL91jFmazOVXi7OmEXir";request_token|s:32:"gXnZKfUL92i6qJ8bHQdDxsDrc55wQXoV";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:7:"custom2";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:7:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";s:7:"columns";a:8:{i:0;s:7:"threads";i:1;s:7:"subject";i:2;s:6:"status";i:3;s:6:"fromto";i:4;s:4:"date";i:5;s:4:"size";i:6;s:4:"flag";i:7;s:10:"attachment";}}folders|a:5:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}s:4:"Sent";a:2:{s:3:"cnt";i:0;s:6:"maxuid";i:0;}s:5:"Trash";a:2:{s:3:"cnt";i:1;s:6:"maxuid";i:1;}s:7:"custom1";a:2:{s:3:"cnt";i:3;s:6:"maxuid";i:3;}s:7:"custom2";a:2:{s:3:"cnt";i:1;s:6:"maxuid";i:1;}}unseen_count|a:5:{s:5:"INBOX";i:0;s:4:"Sent";i:0;s:5:"Trash";i:0;s:7:"custom1";i:3;s:7:"custom2";i:1;}list_mod_seq|s:1:"3";STORAGE_QRESYNC|b:1; 
```


![[Pasted image 20250724141552.png]]
![[Pasted image 20250724150552.png]]


# 📄 Investigation Report: Roundcube Session Behavior


---

## 🧪 Objective

To understand and verify how user session data is managed and stored in the Roundcube mail system, particularly:
- Where session data is stored
- What happens when users log in and out
- How many session records are retained and why
- Whether old sessions are reused or new ones are created

---

## 🔍 Observations

### ✅ Session Storage Location
- Roundcube stores session data in a MySQL/MariaDB table named `session`.
- Each row represents a unique **PHP session**, not a Roundcube user.

### ✅ Session Table Structure
The `session` table contains the following columns:
- `sess_id`: Unique session ID (cookie-based)
- `changed`: Last activity timestamp
- `ip`: Client IP
- `vars`: Base64-encoded PHP session data (contains user data)

---

## 🧪 Tests Performed and Results

### 1. **Login as a user**
- A new session row is created in the `session` table.
- The `vars` column contains user-related information like:
  - `username`
  - `imap_host`, `login_time`
  - UI preferences

### 2. **Logout**
- The session row remains in the table.
- However, most user-specific data in `vars` is cleared.
- The `changed` timestamp is updated.

### 3. **Login with a different user after logout in the same browser session**
- A new session is created.
- The previous session row is altered.(all the colums are altered it's like the new session ecraser the old session)
- Only one session remains active because Roundcube called `session_destroy()` during logout.
### 4. **Login with a different user after logout in different browser session

- A new session is created.
- The previous session row is **not reused**.


### 5. **Login with a different user without logging out**
- A second session row appears in the table (new `sess_id`).
- Roundcube allows concurrent sessions when the previous session is still active (i.e., no logout).



---

## 🧩 Key Findings

| Behavior                                | Observed Outcome                                                                                                                               |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Login creates new session               | ✅ Yes                                                                                                                                          |
| Logout deletes session row              | ❌ No, session remains in DB                                                                                                                    |
| Logout clears session data              | ✅ Yes ("vars column" mostly emptied)                                                                                                           |
| Login after logout reuses session       | ❌ No, session ID changes                                                                                                                       |
| Login with new user (no logout)         | ✅ New session row added                                                                                                                        |
| Only one row appears if logout happened | ✅ Yes for the same browser session, old session cleared + new created. <br>❌ No for different browser session , old session kept + new created |


---

## 🔐 Security and Maintenance Implications

- **Sessions are not automatically deleted** — stale sessions persist in the `session` table.
- Roundcube relies on a `session_lifetime` (default: 10 minutes) but doesn’t clean up expired records.
- Manual or cron-based cleanup is recommended using:

```sql
DELETE FROM session WHERE changed < (UNIX_TIMESTAMP() - 1800);
```
### 6. **Decoded session content**
- Using Base64 decoding + unserialization, confirmed session `vars` include mailbox, language, and UI layout details.