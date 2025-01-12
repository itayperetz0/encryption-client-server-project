import sqlite3
import uuid
import json
import os
from datetime import datetime

# Database file name will be created on same folder as python file
DB_FILE = "clients.db"

def setup_database():
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            uuid BLOB PRIMARY KEY,
            name TEXT NOT NULL,
            public_key TEXT,
            last_seen TEXT NOT NULL,
            aes_key TEXT,
            files TEXT
        )
    """)
    connection.commit()
    connection.close()

def save_clients_to_db(clients):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.executemany("""
        INSERT OR REPLACE INTO clients (uuid, name, public_key, last_seen, aes_key, files)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [
        (
            client['UUID'].bytes,                  # Save UUID as binary
            client['Name'],                       # Save Name
            client['Public Key'],                 # Save Public Key (nullable)
            client['LastSeen'].isoformat(),       # Save LastSeen as ISO string
            client['AES Key'],                    # Save AES Key (nullable)
            json.dumps(client['files'])           # Save files as JSON string
        )
        for client in clients
    ])

    connection.commit()
    connection.close()

def load_clients_from_db():
    # Check if the database file exists
    if not os.path.exists(DB_FILE):
        print("Database file does not exist. Continuing without loading clients.")
        return []

    try:
        connection = sqlite3.connect(DB_FILE)
        cursor = connection.cursor()

        # Fetch all client details
        cursor.execute("SELECT uuid, name, public_key, last_seen, aes_key, files FROM clients")
        rows = cursor.fetchall()

        # Convert rows into client dictionaries
        clients = [
            {
                'UUID': uuid.UUID(bytes=row[0]),          # Convert binary back to UUID
                'Name': row[1],                          # Name
                'Public Key': row[2],                    # Public Key
                'LastSeen': datetime.fromisoformat(row[3]),  # Convert ISO string to datetime
                'AES Key': row[4],                       # AES Key
                'files': json.loads(row[5])              # Convert JSON string back to dictionary
            }
            for row in rows
        ]

        connection.close()
        return clients

    except sqlite3.Error as e:
        print(f"Error while loading clients from the database: {e}")
        return []
