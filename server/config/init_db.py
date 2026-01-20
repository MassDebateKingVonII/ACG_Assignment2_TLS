import os
from dotenv import load_dotenv
from mysql.connector import pooling


load_dotenv()

DB_NAME = os.getenv("DB_NAME")

def init_database():

    db_pool = pooling.MySQLConnectionPool(
        pool_name="mypool",
        pool_size=5,                 # number of connections
        pool_reset_session=True,
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        autocommit = True,
        ssl_disabled= False           # TLS assumed ON
    )
    
    conn = db_pool.get_connection()
    
    try:
        with conn.cursor() as cur:
            # Drop database
            print(f"[*] Dropping database '{DB_NAME}' if exists...")
            cur.execute(f"DROP DATABASE IF EXISTS {DB_NAME}")

            # Create database
            print(f"[*] Creating database '{DB_NAME}'...")
            cur.execute(f"CREATE DATABASE {DB_NAME}")

            # Use the new database
            cur.execute(f"USE {DB_NAME}")
            
            # Create User table
            print("[*] Creating table 'Users'...")
            cur.execute("""
                CREATE TABLE users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    cert_path TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Create FIles Table
            print("[*] Creating table 'encrypted_files'...")
            cur.execute("""
                CREATE TABLE encrypted_files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL UNIQUE,
                    uploaded_by_id INT NOT NULL,
                    file_nonce VARCHAR(24) NOT NULL, -- base64 encoded nonce
                    file_tag VARCHAR(24) NOT NULL,   -- base64 encoded GCM tag
                    file_signature TEXT NOT NULL,
                    enc_dek JSON NOT NULL,           -- stores ciphertext, nonce, tag
                    kek_salt VARCHAR(64) NOT NULL,   -- base64 string
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_user
                        FOREIGN KEY (uploaded_by_id)
                        REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );
            """)
        
    finally:
        conn.close()

    print("Database fully reset and initialized successfully")

if __name__ == "__main__":
    init_database()
