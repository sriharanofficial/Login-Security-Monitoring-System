from flask import Flask, render_template, request, session, redirect, url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from config import DB_CONFIG

app = Flask(__name__)

# Session secret key
app.secret_key = "login-security-project-secret-key"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return "Login Security Monitoring System"


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        if not username or not email or not password:
            return "All fields are required!"

        hashed_password = generate_password_hash(password)

        db = get_db_connection()
        cursor = db.cursor()

        query = """
        INSERT INTO users (username, password, email)
        VALUES (%s, %s, %s)
        """

        try:
            cursor.execute(
                query,
                (username, hashed_password, email)
            )

            db.commit()

        except mysql.connector.Error as error:

            db.rollback()
            cursor.close()
            db.close()

            return f"Registration failed: {error}"

        cursor.close()
        db.close()

        return "User Registered Successfully!"

    return render_template("register.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent")

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        query = """
        SELECT *
        FROM users
        WHERE username = %s
        """

        cursor.execute(query, (username,))
        user = cursor.fetchone()

        # SUCCESSFUL LOGIN
        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            log_query = """
            INSERT INTO login_logs
            (
                user_id,
                username,
                ip_address,
                user_agent,
                status
            )
            VALUES (%s, %s, %s, %s, %s)
            """

            cursor.execute(
                log_query,
                (
                    user["id"],
                    username,
                    ip_address,
                    user_agent,
                    "SUCCESS"
                )
            )

            db.commit()

            cursor.close()
            db.close()

            return redirect(url_for("dashboard"))

        # FAILED LOGIN
        else:

            log_query = """
            INSERT INTO login_logs
            (
                user_id,
                username,
                ip_address,
                user_agent,
                status
            )
            VALUES (%s, %s, %s, %s, %s)
            """

            cursor.execute(
                log_query,
                (
                    None,
                    username,
                    ip_address,
                    user_agent,
                    "FAILED"
                )
            )

            db.commit()

            cursor.close()
            db.close()

            return "Invalid Username or Password!"

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# SECURITY DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    # Login protection
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)


    # -----------------------------------------------------
    # TOTAL USERS
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM users
    """)

    total_users = cursor.fetchone()["total"]


    # -----------------------------------------------------
    # SUCCESSFUL LOGINS
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM login_logs
        WHERE status = 'SUCCESS'
    """)

    successful_logins = cursor.fetchone()["total"]


    # -----------------------------------------------------
    # FAILED LOGINS
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM login_logs
        WHERE status = 'FAILED'
    """)

    failed_logins = cursor.fetchone()["total"]


    # -----------------------------------------------------
    # SUSPICIOUS ATTEMPTS
    #
    # Username with 3 or more failed attempts
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS suspicious_count
        FROM (
            SELECT username
            FROM login_logs
            WHERE status = 'FAILED'
            GROUP BY username
            HAVING COUNT(*) >= 3
        ) AS suspicious_users
    """)

    suspicious_attempts = cursor.fetchone()["suspicious_count"]


    # -----------------------------------------------------
    # SUSPICIOUS USER DETAILS
    # -----------------------------------------------------

    cursor.execute("""
        SELECT
            username,
            ip_address,
            COUNT(*) AS failed_attempts
        FROM login_logs
        WHERE status = 'FAILED'
        GROUP BY username, ip_address
        HAVING COUNT(*) >= 3
        ORDER BY failed_attempts DESC
    """)

    suspicious_users = cursor.fetchall()


    # -----------------------------------------------------
    # LOGIN ACTIVITY
    # -----------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            username,
            ip_address,
            status,
            login_time
        FROM login_logs
        ORDER BY login_time DESC
    """)

    logs = cursor.fetchall()


    cursor.close()
    db.close()


    # -----------------------------------------------------
    # SEND DATA TO DASHBOARD
    # -----------------------------------------------------

    return render_template(
        "dashboard.html",
        logs=logs,
        total_users=total_users,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        suspicious_attempts=suspicious_attempts,
        suspicious_users=suspicious_users
    )


# =========================================================
# USER MANAGEMENT
# =========================================================

@app.route("/users")
def users():

    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            username,
            email,
            role,
            created_at
        FROM users
        ORDER BY id DESC
    """)

    users = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "users.html",
        users=users
    )


# =========================================================
# EDIT USER
# =========================================================

@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        role = request.form["role"]

        if not username or not email:
            cursor.close()
            db.close()
            return "Username and Email are required!"

        query = """
        UPDATE users
        SET username = %s,
            email = %s,
            role = %s
        WHERE id = %s
        """

        cursor.execute(
            query,
            (username, email, role, user_id)
        )

        db.commit()

        cursor.close()
        db.close()

        return """
        <h2>User Updated Successfully!</h2>
        <br>
        <a href="/users">Back to Users</a>
        """

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE id = %s
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    cursor.close()
    db.close()

    if not user:
        return "User not found!"

    return render_template(
        "edit_user.html",
        user=user
    )


# =========================================================
# DELETE USER
# =========================================================

@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute(
        """
        DELETE FROM users
        WHERE id = %s
        """,
        (user_id,)
    )

    db.commit()

    cursor.close()
    db.close()

    return """
    <h2>User Deleted Successfully!</h2>
    <br>
    <a href="/users">Back to Users</a>
    """


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)