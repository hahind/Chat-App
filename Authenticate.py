import sqlite3
import bcrypt
import os

class AuthManager:
    def __init__(self):
        self.dbPath = os.path.join(os.path.dirname(__file__), "database", "users.db")
        self._ensureDBDir()
        self._initDB()

    def _ensureDBDir(self):
        dbDir = os.path.dirname(self.dbPath)
        os.makedirs(dbDir, exist_ok=True)

    def _initDB(self):
        conn = sqlite3.connect(self.dbPath)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, pwdHash TEXT NOT NULL)")
        conn.commit()
        conn.close()

    def registerUser(self, username, password):
        conn = sqlite3.connect(self.dbPath)
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            conn.close()
            return False, "User already exists."
        hashed_owd = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cur.execute("INSERT INTO users (username, pwdHash) VALUES (?, ?)", (username,  hashed_owd))
        conn.commit()
        conn.close()
        return True, "User registered successfully."

    def loginUser(self, username, password):
        conn = sqlite3.connect(self.dbPath)
        cur = conn.cursor()
        cur.execute("SELECT pwdHash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return False, "User not found."
        if bcrypt.checkpw(password.encode("utf-8"), row[0]):
            return True, "Login successful."
        return False, "Incorrect password."

if __name__ == "__main__":
    authMgr = AuthManager()
    res, msg = authMgr.registerUser("Mike", "123blabla")
    print(res, msg)
    res, msg = authMgr.loginUser("Mike", "123blabla")
    print(res, msg)
