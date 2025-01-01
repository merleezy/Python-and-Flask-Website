from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3 as sql
from Encryption import AESCipher

app = Flask(__name__)
app.secret_key = "something_secret_and_unique"

# Encryption key and IV (example values provided)
key = b'BLhgpCL81fdLBk23HkZp8BgbT913cqt0'
iv = b'OWFJATh1Zowac2xr'
cipher = AESCipher(key, iv)

def init_db():
    with sql.connect("baking_contest.db") as conn:
        cursor = conn.cursor()

        # Modify table if needed: Fields remain TEXT, but now we will store encrypted data in them
        conn.execute("""
        CREATE TABLE IF NOT EXISTS BakingContestUsers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            phone TEXT NOT NULL,
            security_level INTEGER NOT NULL,
            login_password TEXT NOT NULL
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS BakingContestEntries (
            entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name_of_baking_item TEXT NOT NULL,
            num_excellent_votes INTEGER DEFAULT 0,
            num_ok_votes INTEGER DEFAULT 0,
            num_bad_votes INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES BakingContestUsers(id)
        )
        """)

        # Check if BakingContestUsers is empty, then insert static encrypted data
        cursor.execute("SELECT COUNT(*) FROM BakingContestUsers")
        people_count = cursor.fetchone()[0]
        if people_count == 0:
            # Encrypt these sensitive fields
            users_to_insert = [
                ('Alice Johnson', 25, '999-555-1234', 1, 'password123'),
                ('Bob Smith', 33, '999-555-5678', 2, 'password456'),
                ('Charlie Brown', 41, '999-555-9876', 3, 'password789')
            ]
            encrypted_users = []
            for (uname, uage, uphone, usec, upass) in users_to_insert:
                enc_name = cipher.encrypt(uname.encode('utf-8')).decode('utf-8')
                enc_phone = cipher.encrypt(uphone.encode('utf-8')).decode('utf-8')
                enc_pass = cipher.encrypt(upass.encode('utf-8')).decode('utf-8')
                encrypted_users.append((enc_name, uage, enc_phone, usec, enc_pass))

            cursor.executemany("""
                INSERT INTO BakingContestUsers (name, age, phone, security_level, login_password)
                VALUES (?, ?, ?, ?, ?)
            """, encrypted_users)
            print("Inserted 3 encrypted records into BakingContestUsers.")

        # Check if BakingContestEntries table is empty, insert sample data (no encryption needed)
        cursor.execute("SELECT COUNT(*) FROM BakingContestEntries")
        entries_count = cursor.fetchone()[0]
        if entries_count == 0:
            # Fetch user ids from the BakingContestUsers table (no need to decrypt user IDs)
            cursor.execute("SELECT id FROM BakingContestUsers")
            user_ids = [row[0] for row in cursor.fetchall()]
            # Sample entries (not encrypted)
            cursor.executemany("""
                INSERT INTO BakingContestEntries (user_id, name_of_baking_item, num_excellent_votes, num_ok_votes, num_bad_votes)
                VALUES (?, ?, ?, ?, ?)
            """, [
                (user_ids[0], 'Chocolate Cake', 30, 10, 5),
                (user_ids[1], 'Vanilla Cupcakes', 40, 5, 3),
                (user_ids[2], 'Apple Pie', 20, 15, 10)
            ])
            print("Inserted 3 records into BakingContestEntries.")

        conn.commit()

def validate_input(name, age, phone, security_level, password):
    errors = []
   
    # Name Validation
    if not name.strip():
        errors.append("Name must not be empty or contain only spaces.")
      
    # Age Validation
    try:
        age_val = int(age)
        if age_val <= 0 or age_val >= 121:
            errors.append("Age must be a whole number between 1 and 121.")
    except ValueError:
        errors.append("Age must be a valid number.")
       
    # Phone Number Validation
    if not phone.strip():
        errors.append("Phone number must not be empty or contain only spaces.")
       
    # Security Level Validation
    try:
        sec_level = int(security_level)
        if sec_level < 1 or sec_level > 3:
            errors.append("Security level must be a number between 1 and 3.")
    except ValueError:
        errors.append("Security level must be a valid number.")
        
    # Password Validation
    if not password.strip():
        errors.append("Password must not be empty or contain only spaces.")
        
    return errors

def validate_entry_input(name_of_baking_item, excellent_votes, ok_votes, bad_votes):
    errors = []
    # Name of Baking Item Validation
    if not name_of_baking_item.strip():
        errors.append("Name of Baking Item must not be empty or contain only spaces.")

    def validate_votes(value, field_name):
        try:
            val = int(value)
            if val < 0:
                errors.append(f"{field_name} must be a non-negative integer.")
        except ValueError:
            errors.append(f"{field_name} must be a valid whole number.")

    validate_votes(excellent_votes, "Number of Excellent Votes")
    validate_votes(ok_votes, "Number of OK Votes")
    validate_votes(bad_votes, "Number of Bad Votes")

    return errors

@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    security_level = session["security_level"]
    return render_template("index.html", username=username, security_level=security_level)

@app.route('/add-user')
def add_user():
    if "username" not in session:
        return redirect(url_for("login"))
    elif session["security_level"] < 3:
        return "Page not found", 404
    return render_template('add-baking-contest-user.html')

@app.route('/submit', methods = ['POST', 'GET'])
def submit():
    if request.method == 'GET':
        return redirect(url_for("home"))

    name = request.form.get("Name", "").strip()
    age = request.form.get("Age", "").strip()
    phone = request.form.get("Phone Number", "").strip()
    security_level = request.form.get("Security Level", "").strip()
    password = request.form.get("Password", "").strip()

    errors = validate_input(name, age, phone, security_level, password)
    if errors:
        return render_template("result.html", errors=errors)

    # Encrypt sensitive fields before inserting
    enc_name = cipher.encrypt(name.encode('utf-8')).decode('utf-8')
    enc_phone = cipher.encrypt(phone.encode('utf-8')).decode('utf-8')
    enc_pass = cipher.encrypt(password.encode('utf-8')).decode('utf-8')

    with sql.connect("baking_contest.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO BakingContestUsers (name, age, phone, security_level, login_password)
            VALUES (?, ?, ?, ?, ?)
        """, (enc_name, int(age), enc_phone, int(security_level), enc_pass))
        conn.commit()
        
    return render_template("result.html", message="Record added successfully!")

@app.route('/users')
def contest_results():
    if "username" not in session:
        return redirect(url_for("login"))
    elif session["security_level"] < 2:
        return "Page not found", 404

    with sql.connect("baking_contest.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, age, phone, security_level, login_password FROM BakingContestUsers")
        users = cursor.fetchall()

    # Decrypt fields before displaying
    decrypted_users = []
    for (enc_name, uage, enc_phone, usec, enc_pass) in users:
        dec_name = cipher.decrypt(enc_name)
        dec_phone = cipher.decrypt(enc_phone)
        dec_pass = cipher.decrypt(enc_pass)
        decrypted_users.append((dec_name, uage, dec_phone, usec, dec_pass))

    return render_template('list-baking-contest-users.html', users=decrypted_users)

@app.route('/results')
def contest_users():
    if "username" not in session:
        return redirect(url_for("login"))
    elif session["security_level"] < 3:
        return "Page not found", 404

    # No encryption needed for entries
    with sql.connect("baking_contest.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT entry_id, user_id, name_of_baking_item, num_excellent_votes, num_ok_votes, num_bad_votes
            FROM BakingContestEntries
        """)
        entries = cursor.fetchall()  
        
    return render_template('baking-contest-results.html', entries=entries)

@app.route("/my-results")
def my_results():
    if "username" not in session:
        return redirect(url_for("login"))
    elif session["security_level"] < 1:
        return "Page not found", 404

    user_id = session.get("user_id")

    # Entries are not encrypted
    with sql.connect("baking_contest.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name_of_baking_item, num_excellent_votes, num_ok_votes, num_bad_votes
            FROM BakingContestEntries
            WHERE user_id = ?
        """, (user_id,))
        entries = cursor.fetchall()

    return render_template('my-results.html', entries=entries)

@app.route("/add-entry", methods=["GET", "POST"])
def add_entry():
    if "username" not in session:
        return redirect(url_for("login"))
    elif session["security_level"] < 1:
        return "Page not found", 404

    if request.method == "POST":
        name_of_baking_item = request.form.get("NameOfBakingItem", "").strip()
        excellent_votes = request.form.get("NumExcellentVotes", "").strip()
        ok_votes = request.form.get("NumOkVotes", "").strip()
        bad_votes = request.form.get("NumBadVotes", "").strip()

        errors = validate_entry_input(name_of_baking_item, excellent_votes, ok_votes, bad_votes)
        if errors:
            return render_template("result.html", errors=errors)

        user_id = session.get("user_id")
        with sql.connect("baking_contest.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO BakingContestEntries (user_id, name_of_baking_item, num_excellent_votes, num_ok_votes, num_bad_votes)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, name_of_baking_item, int(excellent_votes), int(ok_votes), int(bad_votes)))
            conn.commit()

        return render_template("result.html", message="Contest Entry added successfully!")
    else:
        return render_template("add-entry.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Encrypt username & password for comparison
        enc_username = cipher.encrypt(username.encode('utf-8')).decode('utf-8')
        enc_password = cipher.encrypt(password.encode('utf-8')).decode('utf-8')

        with sql.connect("baking_contest.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, security_level
                FROM BakingContestUsers
                WHERE name = ? AND login_password = ?
            """, (enc_username, enc_password))
            user = cursor.fetchone()

            if user:
                # Decrypt the name before storing in session
                dec_name = cipher.decrypt(user[1])
                session["user_id"] = user[0]
                session["username"] = dec_name
                session["security_level"] = user[2]
                return redirect(url_for("home"))
            else:
                return render_template("login.html", error="Invalid username and/or password!")
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
