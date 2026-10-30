
from flask import (
    Flask, request, session, redirect,
    render_template_string, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

DB_NAME = "secure_users.db"


def setup_database():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        conn.execute(
            "INSERT OR IGNORE INTO users VALUES (?, ?)",
            ("demo", generate_password_hash("DemoPass123!"))
        )


@app.route("/")
def home():
    name = request.args.get("name", "visitor")

    # SECURITY CONTROL 1: Validate input length
    if len(name) > 80:
        abort(400, "Input is too long")

    # SECURITY CONTROL 2: Automatic HTML escaping
    return render_template_string(
        "<h2>Hello {{ name }}</h2>",
        name=name
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if not username or len(username) > 50 or len(password) > 128:
            abort(400, "Invalid input")

        # SECURITY CONTROL 3: Parameterized SQL
        with sqlite3.connect(DB_NAME) as conn:
            user = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        # SECURITY CONTROL 4: Verify hashed password
        if user and check_password_hash(user[0], password):
            # Clear prior session data after successful authentication
            session.clear()
            session["username"] = username
            return redirect("/profile")

        message = "Invalid username or password"

    return render_template_string("""
        <h2>Login</h2>
        <p>{{ message }}</p>
        <form method="post">
            <input name="username" maxlength="50"
                   placeholder="Username" required>
            <input name="password" type="password" maxlength="128"
                   placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    """, message=message)


@app.route("/profile")
def profile():
    # SECURITY CONTROL 5: Require authentication
    username = session.get("username")

    if not username:
        return redirect("/login")

    return render_template_string(
        "<h2>Welcome, {{ username }}</h2>",
        username=username
    )


@app.route("/logout")
def logout():
    # SECURITY CONTROL 6: Clear session data
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    setup_database()
    app.run(debug=False)
