
from flask import Flask, request, session, redirect, render_template_string
import sqlite3

app = Flask(__name__)
app.secret_key = "weak-secret"

DB_NAME = "vulnerable_users.db"


def setup_database():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        conn.execute(
            "INSERT OR IGNORE INTO users VALUES (?, ?)",
            ("demo", "DemoPass123!")
        )


@app.route("/")
def home():
    name = request.args.get("name", "visitor")

    # VULNERABILITY 1: Unsafe HTML interpolation (XSS)
    return render_template_string(f"<h2>Hello {name}</h2>")


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILITY 2: SQL injection
        query = (
            "SELECT username FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )

        with sqlite3.connect(DB_NAME) as conn:
            user = conn.execute(query).fetchone()

        if user:
            # VULNERABILITY 3: Session does not regenerate
            # and relies on a weak application secret.
            session["username"] = username
            return redirect("/profile")

        message = "Invalid credentials"

    return render_template_string("""
        <h2>Login</h2>
        <p>{{ message }}</p>
        <form method="post">
            <input name="username" placeholder="Username">
            <input name="password" type="password"
                   placeholder="Password">
            <button type="submit">Login</button>
        </form>
    """, message=message)


@app.route("/profile")
def profile():
    # VULNERABILITY 4: Missing authentication check
    return "Welcome to the profile page!"


@app.route("/logout")
def logout():
    # VULNERABILITY 5: Session is not cleared
    return "Logout requested, but session remains active."


if __name__ == "__main__":
    setup_database()
    app.run(debug=False)
