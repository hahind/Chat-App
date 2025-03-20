import sqlite3 
import bcrypt 
import os 

    # Class responsible for managing user authentication (register & login)
class AuthManager:
    def __init__(self):
    # Set the path to the SQLite database file in a subfolder named "database"
        self.dbPath = os.path.join(os.path.dirname(__file__), "database", "users.db")
        self._ensureDBDir()  
        self._initDB()

    # Creates the "database" directory if it does not exist
    def _ensureDBDir(self):
        dbDir = os.path.dirname(self.dbPath)
        os.makedirs(dbDir, exist_ok=True)

    # Initializes the SQLite database and creates the users table if it doesn't exist
    def _initDB(self):
        conn = sqlite3.connect(self.dbPath)  # Connect to SQLite database
        cur = conn.cursor()
    # Create table with username (primary key) and hashed password
        cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, pwdHash TEXT NOT NULL)")
        conn.commit()
        conn.close()

    # Registers a new user with hashed password; returns success flag and message
    def registerUser(self, username, password):
        conn = sqlite3.connect(self.dbPath)
        cur = conn.cursor()
    # Check if username already exists
        cur.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            conn.close()
            return False, "User already exists."

        hashed_owd = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    # Store username and hashed password in the database
        cur.execute("INSERT INTO users (username, pwdHash) VALUES (?, ?)", (username, hashed_owd))
        conn.commit()
        conn.close()
        return True, "User registered successfully."

    # Logs in an existing user; checks if password matches the stored hash
    def loginUser(self, username, password):
        conn = sqlite3.connect(self.dbPath)
        cur = conn.cursor()
    # Retrieve the hashed password for the given username
        cur.execute("SELECT pwdHash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return False, "User not found."

    # Compare entered password with stored hash
        if bcrypt.checkpw(password.encode("utf-8"), row[0]):
            return True, "Login successful."
        return False, "Incorrect password."

    # Test block to demonstrate registration and login 
if __name__ == "__main__":
    authMgr = AuthManager()

    res, msg = authMgr.registerUser("Mike", "123blabla")
    print(res, msg)

    res, msg = authMgr.loginUser("Mike", "123blabla")
    print(res, msg)
