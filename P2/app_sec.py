from datetime import timedelta
import shutil
import traceback
from flask import (
    Flask,
    Blueprint,
    render_template,
    session,
    redirect,
    request,
    url_for,
    flash,
    send_from_directory,
)
from flask_mail import Mail, Message
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
import sqlite3
import base64
import os
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_session import Session
import signal
import sys
from passwordmeter import test
import hashlib
import time
from password_strength import PasswordPolicy
import requests
import random
import bleach


def generate_key():
    key = os.urandom(32)  # 256-bit key for AES
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

generate_key()


password_policy = PasswordPolicy.from_names(
    length=12,
    uppercase=1,
    numbers=1,
    special=1,
)

def load_key():
    return open('secret.key', 'rb').read()

def encrypt_message(message):
    key = load_key()
    nonce = os.urandom(16)  # Gerando um nonce
    cipher = Cipher(algorithms.AES(key), modes.CFB(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    encrypted_message = base64.urlsafe_b64encode(nonce + encrypted).decode('utf-8')
    return encrypted_message

def decrypt_message(encrypted_message):
    try:
        key = load_key()
        encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message)
        nonce = encrypted_message_bytes[:16]  # O nonce está nos primeiros 16 bytes
        encrypted = encrypted_message_bytes[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Erro durante a descriptografia: {e}")
        return None





# Teste
def test_encryption_decryption():
    original_message = "dsaokxASD2310!+"
    encrypted_message = encrypt_message(original_message)
    encrypted_message = "0LNhjBhC9-CJ4AiNyIMwMEXmhHn1TkaZbvYyIQpC5g=="
    decrypted_message = decrypt_message(encrypted_message)
    
    print(f"Original message: {original_message}")
    print(f"Encrypted message: {encrypted_message}")
    print(f"Decrypted message: {decrypted_message}")
    
    if decrypted_message == original_message:
        print("Teste de criptografia e descriptografia bem-sucedido!")
    else:
        print(f"Falha no teste. Mensagem original: {original_message}, Mensagem descriptografada: {decrypted_message}")

# test_encryption_decryption()


def is_password_breached(password):
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    hashes = response.text.split("\n")
    for h in hashes:
        if h.startswith(suffix):
            return True
    return False



app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 5 Megabytes

UPLOAD_FOLDER = 'path/to/upload_folder'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Certifique-se de que o diretório de upload existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'detitore@gmail.com'
app.config['MAIL_PASSWORD'] = 'B@tata10'

mail = Mail(app)

# Set the secret key directly
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "safe_version")

SERVER_PATH = os.path.dirname(os.path.abspath(__file__))
DB_STRING = os.path.join(SERVER_PATH, "database/shop_sec.db")
public_path = os.path.join(os.path.dirname(__file__), "public")

app.template_folder = public_path

# Initialize the Flask-Session extension
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "./flask_safe_session/data"
app.permanent_session_lifetime = timedelta(minutes=10)
Session(app)


# create the Blueprint
initialize_bp = Blueprint("initialize", __name__)


# Define a function to initialize the 'user_ids' list in the session
def initialize_session():
    if "user_id" not in session:
        session["user_id"] = []


# Register the before_app_request decorator with the Blueprint
initialize_bp.before_app_request(initialize_session)

def load_compromised_passwords():
    with open("compromised_passwords.txt", "r") as file:
        return {line.strip() for line in file}


compromised_passwords = load_compromised_passwords()


def is_password_compromised(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password in compromised_passwords


def is_shared_or_default_account(username):
    shared_default_accounts = ["root", "admin", "sa"]

    return username.lower() in shared_default_accounts


# Register the Blueprint with the app
app.register_blueprint(initialize_bp)


@app.route("/")
def home():
    return redirect(url_for("index"))


@app.route("/index_page")
def index():
    if "user_id" in session and session["user_id"] != []:
        conn = sqlite3.connect("database/shop_sec.db")
        c = conn.cursor()
        query = f"SELECT username FROM users WHERE user_id=?"
        res = c.execute(query, (get_current_user_id(),))
        print("agora tou aqui")
        user_name = res.fetchone()[0]

        return render_template("index_sec.html", user_name=user_name)
    else:
        return render_template("index_sec.html", user_name=None)


@app.route("/login_page")
def login_page():
    return render_template("login_sec.html")


@app.route("/register_page")
def register_page():
    return render_template("register.html")

@app.route("/two_factor_page")
def two_factor_page():
    session["user_id"].append(generate_verification_code())
    conn = sqlite3.connect("database/shop_sec.db")
    c = conn.cursor()
    res = c.execute("SELECT * FROM users WHERE user_id=?", (session["user_id"][0],))
    data = res.fetchone()
    conn.close()
    
    send_email(data[2],session["user_id"][-1])

    return render_template("two_factor.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        session["user_id"].pop()
    return redirect("/")


@app.route("/checkOut")
def checkOut():
    index = request.args.get("index")
    conn = sqlite3.connect("database/shop_sec.db")
    cursor = conn.cursor()
    cursor.execute(
        f'SELECT user_name, user_comment, file_name FROM fileComments WHERE post_id="{index}"'
    )
    comments = cursor.fetchall()
    conn.close()

    return render_template("checkOut.html", keys=index, comments=comments)



@app.route("/change_pass_sec_page")
def changePass_sec_page():
    error_message = request.args.get("error")

    if error_message:
        return render_template("change_pass_sec_page.html", error=error_message)
    return render_template("change_pass_sec_page.html")


@app.route("/change_pass_sec", methods=["POST"])
def change_pass_sec():
    conn = sqlite3.connect("database/shop_sec.db")
    c = conn.cursor()
    # stop here
    user_name = request.form["user_name"]
    old_pass = request.form["old_password"]
    new_pass = request.form["newPassword"]
    confirmed = request.form["confirmPassword"]

    # confirm user_name exists
    query = f"SELECT * FROM users WHERE username = ?"
    res = c.execute(query, (user_name,))
    password = res.fetchone()

    if (
        password is not None
        and len(old_pass) > 0
        and len(new_pass) > 0
        and len(confirmed) > 0
    ):
        old_exist = bcrypt.checkpw(old_pass.encode("utf-8"), password[3])
        if new_pass == confirmed and old_exist:
            update_query = f"UPDATE users SET password = ? WHERE username = ?"
            new_pass = bcrypt.hashpw(new_pass.encode("utf-8"), bcrypt.gensalt())
            c.execute(update_query, (new_pass, user_name))
            conn.commit()
            conn.close()
            flash(
                "Your authentication factor has been changed. Please log in again.",
                "info",
            )
            return render_template("login_sec.html")
        else:
            if not (old_exist):
                return redirect(
                    url_for("changePass_sec_page", error="Old Password dosent match")
                )
            return redirect(
                url_for("changePass_sec_page", error="Passwords do not match")
            )
    else:
        return redirect(
            url_for("changePass_sec_page", error="Username or password Incorrect")
        )


login_attempts = {}
@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        name = request.form["name"].strip()
        password = request.form["password"].strip()

        if name in login_attempts:
            elapsed_time = time.time() - login_attempts[name]["last_attempt_time"]
            if login_attempts[name]["failed_attempts"] >= 5 and elapsed_time < 300:
                flash("Conta bloqueada devido a muitas tentativas falhadas. Tente novamente mais tarde.", "error")
                return redirect(url_for("login_page"))

        conn = sqlite3.connect("database/shop_sec.db")
        c = conn.cursor()
        res = c.execute("SELECT * FROM users WHERE username=?", (name,))
        data = res.fetchone()
        conn.close()
        print(data)
        if data is not None:
            print("Vou te dizer a pass de maneira encriptada")
            print(data[3])
            encrypted_password = data[3]
            print(f"Encrypted password retrieved from DB: {encrypted_password}")
            try:
                decrypted_password = decrypt_message(encrypted_password)
            except Exception as e:
                flash("Erro ao descriptografar a senha.", "error")
                return redirect(url_for("login_page"))

            if password == decrypted_password:
                session['user_id'] = [data[0]]
                print("TOU AQUI")
                if data[-1] == "":
                    print("acho q agora tou AQUI")
                    return redirect(url_for("index"))
                else:
                    return redirect(url_for("two_factor_page"))
            else:
                if name in login_attempts:
                    login_attempts[name]["failed_attempts"] += 1
                    login_attempts[name]["last_attempt_time"] = time.time()
                else:
                    login_attempts[name] = {"failed_attempts": 1, "last_attempt_time": time.time()}
                flash("Incorrect Password", "error")
                return redirect(url_for("login_page"))
        else:
            flash("Username or password incorrect!", "error")
            return redirect(url_for("login_page"))

    return render_template("login_page_sec.html")



@app.route("/2FA", methods=["POST"])
def tFactor():
    code = session["user_id"].pop()
    if code == request.form.get("2FA"):
        redirect(url_for("index"))
    else:
        redirect(url_for("two_factor_page"))


def send_email(to:str, verification_code:int):
    subject = "Verification Code for Two-Factor Authentication"
    body = f"Your verification code is: {verification_code}"
    msg = Message(subject, recipients=[to], body=body)

    mail.send(msg)

def generate_verification_code():
    return str(random.randint(100000, 999999))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        name = request.form["name"]
        name = name.strip()
        password = request.form["password"]
        password = password.strip()
        confirm_password = request.form["confirm_password"]
        two_factor = request.form["2faCode"]

        # Remoção de múltiplos espaços consecutivos
        password = " ".join(password.split())
        password_strength, _ = test(password)
        strength_threshold = 0.8
        

        if email == "":
            flash("Email can't be empty!", "error")
            return redirect("/register")
        if name == "":
            flash("Name can't be empty!", "error")
            return redirect("/register")
        if is_shared_or_default_account(name):
            flash("Username is not allowed", "error")
            return redirect("/register")
        if password == "":
            flash("Password can't be empty!", "error")
            return redirect("/register")
        
        if password_policy.test(password) != []:
            flash("The password does not fulfills the minimum security policy.", "error")
            return redirect("/register")
        if is_password_breached(password):
            flash("A senha foi comprometida e não pode ser usada.", "error")
            return redirect("/register")
        # Verificação do comprimento da senha
        if len(password) < 12 or (len(password) > 64 and len(password) < 128):
            flash("Password must be between 12 and 128 characters long!", "error")
            return redirect("/register")
        # Verificação de caracteres Unicode imprimíveis
        if not all(
            32 <= ord(char) < 127
            or 127 <= ord(char) < 55296
            or 57343 < ord(char) < 1114112
            for char in password
        ):
            flash(
                "Passwords must only contain printable Unicode characters, including language neutral characters and Emojis.",
                "error",
            )
            return redirect("/register")
        if password_strength < strength_threshold:
            flash(
                "Password is not strong enough. Please use a stronger password.",
                "error",
            )
            return redirect("/register")
        if is_password_compromised(password):
            flash(
                "Password is compromised. Please choose a different password.", "error"
            )
            return redirect("/register_page")
        if password != confirm_password:
            flash("Password do not match!", "error")
            return redirect("/register")

        conn = sqlite3.connect("database/shop_sec.db")
        c = conn.cursor()
        c.execute(
            "SELECT * FROM users WHERE username=? OR email=?",
            (
                name,
                email,
            ),
        )
        user = c.fetchone()
        if user is not None:
            if user[1] == name:
                flash("name already exists", "erro")
                return redirect(url_for("register_page"))
            else:
                flash("email already exists", "erro")
            return redirect(url_for("register_page"))
        
        encrypted_password = encrypt_message(password)
        print("Encrypted Password Stored in DB:", encrypted_password)

        c.execute(
            "INSERT INTO users (email, username, password, two_factor) VALUES (?, ?, ?, ?)",
            (email, name, encrypted_password, two_factor)
        )
        conn.commit()
        conn.close()
        return redirect(url_for("login_page"))
    else:
        print("Error in register")
        return render_template("register.html")

UPLOAD_FOLDER = 'path/to/upload_folder'
MAX_FILE_SIZE = 1 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILES_PER_USER = 10

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)



@app.route("/submit_comment", methods=["POST"])
def submit_comment():
    if 'user_id' in session:
        try:
            comment_text = request.form.get('comment_text')
            post_id = request.form.get('product_id')
            file = request.files.get('comment_image')
            
            conn = sqlite3.connect("database/shop_sec.db")
            c = conn.cursor()
            # Get the current username
            query = f'SELECT username FROM users WHERE user_id=?'
            user_id = get_current_user_id()
            print(f"User ID: {user_id}")
            res = c.execute(query, (get_current_user_id(),))
            print("aqui ainda da")
            user_name = res.fetchone()[0]
            print("aqui ja nao")

            file_path = None
            if file:
                file_name = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, file_name)
                file.save(file_path)
                file_content = file.read()
                
                # Check if the user has previously uploaded files
                c.execute("SELECT file_count FROM fileComments WHERE post_id=? AND user_name=?", (post_id, user_name))
                result = c.fetchone()

                if result:
                    file_count = result[0]
                    
                    if file_count >= MAX_FILES_PER_USER:
                        flash(f"You have reached the maximum number of files ({MAX_FILES_PER_USER})", "error")
                        return redirect(url_for('checkOut', index=post_id))
                    
                    
                    file_count =+ 1
                    
                    # Update the file count for the existing record
                    c.execute("""
                        UPDATE fileComments
                        SET file_count=?
                        WHERE post_id=? AND user_name=?
                    """, (file_count, post_id, user_name))
                    
                    # Update the file count and insert the new file
                    c.execute("""
                    INSERT INTO fileComments (post_id, user_id, user_name, user_comment, file_name, file_content)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (post_id, get_current_user_id(), user_name, comment_text, file_name, file_content))
                else:
                    file_count = 1
                    # Insert new record with file info
                    c.execute("""
                        INSERT INTO fileComments (post_id, user_id, user_name, user_comment, file_name, file_count, file_content)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (post_id, get_current_user_id(), user_name, comment_text, file_name, file_count, file_content))
            else:
                # Insert comment without file
                print("n ha ficheiro")
                c.execute("""
                    INSERT INTO fileComments (post_id, user_id, user_name, user_comment)
                    VALUES (?, ?, ?, ?)
                """, (post_id, get_current_user_id(), user_name, comment_text))

            conn.commit()
            conn.close()
            return redirect(url_for('checkOut', index=post_id))
        except Exception as e:
            print(f"An error occurred: {e}")
            flash('An error occurred while submitting your comment', 'error')
            return redirect(url_for('checkOut', index=post_id))
    else:
        flash('Must login to comment', 'error')
        return redirect(url_for('login_page'))




    
    
def get_current_user_name():
    conn = sqlite3.connect("database/shop_sec.db")
    c = conn.cursor()
    print("antes")
    c.execute("SELECT username FROM users WHERE user_id=?", (session.get('user_id'),))
    print("func")
    
    user_name = c.fetchone()[0]
    conn.close()
    
    return user_name


# function to retriver the id of the current user
app.route("/current_user_id")
def get_current_user_id():
    if "user_id" in session and session["user_id"] != []:
        return session["user_id"][-1]
    else:
        return "No user logged in"


# Erro handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template("Error/404.html", error_code=404), 404


@app.errorhandler(Exception)
def internal_server_error(error):
    return render_template("Error/500.html", error_code=500), 500


# Section for clear session data in case
def shutdown(signum, frame):
    clear_session_data()
    print("Shutting down gracefully...")
    sys.exit(0)


# Register the signal handler
signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


def clear_session_data():
    # Delete session data files in the specified directory
    session_dir = app.config["SESSION_FILE_DIR"]
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir)
    else:
        print(f"Session data directory does not exist: {session_dir}")


if __name__ == "__main__":
    app.run(debug=True)
