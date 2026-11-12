
import sqlite3
from flask import (
    Flask, jsonify, render_template, request, redirect, url_for, flash, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from database import init_db, get_db_connection


app = Flask(__name__)

app.secret_key = "artist-corner-hub-dev-key"


# Check whether a user is logged in
def login_required(route):
    @wraps(route)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("login"))

        return route(*args, **kwargs)

    return wrapper


# Home page
@app.route("/")
def index():
    return render_template("index.html")


# User registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please complete all fields.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        connection = get_db_connection()

        try:
            connection.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )
            connection.commit()

            flash("Your account has been created. You can now log in.", "success")
            return redirect(url_for("login"))

        except Exception:
            flash("That email is already registered.", "error")
            return redirect(url_for("register"))

        finally:
            connection.close()

    return render_template("register.html")


# User login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db_connection()

        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("dashboard"))

        flash("Incorrect email or password.", "error")

    return render_template("login.html")


# User dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# View the logged-in user's artist profile
@app.route("/profile")
@login_required
def artist_profile():
    connection = get_db_connection()

    try:
        profile = connection.execute(
            "SELECT * FROM artist_profiles WHERE user_id = ?",
            (session["user_id"],)
        ).fetchone()
    finally:
        connection.close()

    if profile is None:
        return jsonify({"error": "Artist profile not found."}), 404

    return jsonify({"profile": dict(profile)})


# Create the logged-in user's artist profile
@app.route("/profile/create", methods=["POST"])
@login_required
def create_artist_profile():
    fields = ("full_name", "biography", "skills", "interests", "profile_image")
    submitted = request.get_json() if request.is_json else request.form
    if request.is_json and not isinstance(submitted, dict):
        return jsonify({"error": "The request body must be a JSON object."}), 400

    values = {}

    for field in fields:
        value = submitted.get(field, "")
        if not isinstance(value, str):
            return jsonify({"error": f"{field} must be a string."}), 400
        values[field] = value.strip()

    connection = get_db_connection()

    try:
        connection.execute(
            """
            INSERT INTO artist_profiles (
                user_id, full_name, biography, skills, interests, profile_image
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                values["full_name"],
                values["biography"],
                values["skills"],
                values["interests"],
                values["profile_image"]
            )
        )
        connection.commit()
        profile = connection.execute(
            "SELECT * FROM artist_profiles WHERE user_id = ?",
            (session["user_id"],)
        ).fetchone()
    except sqlite3.IntegrityError:
        connection.rollback()
        return jsonify({"error": "An artist profile already exists."}), 409
    finally:
        connection.close()

    return jsonify({"profile": dict(profile)}), 201


# Update the logged-in user's artist profile
@app.route("/profile/edit", methods=["POST", "PUT", "PATCH"])
@login_required
def edit_artist_profile():
    fields = ("full_name", "biography", "skills", "interests", "profile_image")
    submitted = request.get_json() if request.is_json else request.form
    if request.is_json and not isinstance(submitted, dict):
        return jsonify({"error": "The request body must be a JSON object."}), 400

    values = {}

    for field in fields:
        if field in submitted:
            value = submitted[field]
            if not isinstance(value, str):
                return jsonify({"error": f"{field} must be a string."}), 400
            values[field] = value.strip()

    if not values:
        return jsonify({"error": "Provide at least one profile field to update."}), 400

    assignments = ", ".join(f"{field} = ?" for field in values)
    connection = get_db_connection()

    try:
        cursor = connection.execute(
            f"""
            UPDATE artist_profiles
            SET {assignments}, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
            """,
            (*values.values(), session["user_id"])
        )

        if cursor.rowcount == 0:
            connection.rollback()
            return jsonify({"error": "Artist profile not found."}), 404

        connection.commit()
        profile = connection.execute(
            "SELECT * FROM artist_profiles WHERE user_id = ?",
            (session["user_id"],)
        ).fetchone()
    finally:
        connection.close()

    return jsonify({"profile": dict(profile)})


# User logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    with app.app_context():
        init_db()

    app.run(debug=True)
