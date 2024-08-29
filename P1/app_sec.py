from datetime import timedelta
import shutil
from flask import Flask, Blueprint, render_template, session, redirect, request, url_for, flash, send_from_directory
import sqlite3
import os
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session  
import signal
import sys     
import bleach

app = Flask(__name__)

# Set the secret key directly
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'safe_version')

SERVER_PATH = os.path.dirname(os.path.abspath(__file__))
DB_STRING = os.path.join(SERVER_PATH, 'database/shop_sec.db')
public_path = os.path.join(os.path.dirname(__file__), 'public')

app.template_folder = public_path

# Initialize the Flask-Session extension
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_safe_session/data'
app.permanent_session_lifetime = timedelta(minutes=10)
Session(app)


#create the Blueprint
initialize_bp = Blueprint('initialize', __name__)

# Define a function to initialize the 'user_ids' list in the session
def initialize_session():
    if 'user_id' not in session:
        session['user_id'] = []

# Register the before_app_request decorator with the Blueprint
initialize_bp.before_app_request(initialize_session)

# Register the Blueprint with the app
app.register_blueprint(initialize_bp)
@app.route('/')
def home():
    return redirect(url_for('index'))
    

@app.route("/index_page")
def index():
    if 'user_id' in session and session['user_id'] != []:
        conn = sqlite3.connect("database/shop_sec.db")
        c = conn.cursor()
        query = f'SELECT username FROM users WHERE user_id=?'
        res = c.execute(query, str(get_current_user_id()))
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

@app.route("/logout")
def logout():

    if 'user_id' in session:
        session['user_id'].pop()
    return redirect("/")

@app.route("/checkOut")
def checkOut():
    index = request.args.get('index')
    conn = sqlite3.connect("database/shop_sec.db")  # Replace with your actual database file
    cursor = conn.cursor()
    cursor.execute(f'SELECT user_name, user_comment FROM comments WHERE post_id="{index}"')
    comments = cursor.fetchall()
    conn.close()
    
    return render_template("checkOut.html", keys=index, comments=comments)

@app.route("/change_pass_sec_page")
def changePass_sec_page():
    error_message = request.args.get('error')

    if error_message:
        return render_template('change_pass_sec_page.html', error=error_message)
    return render_template("change_pass_sec_page.html")

@app.route("/change_pass_sec", methods=["POST"])
def change_pass_sec():
    conn = sqlite3.connect('database/shop_sec.db')
    c = conn.cursor()
    user_name = request.form["user_name"]
    old_pass = request.form["old_password"]
    new_pass = request.form["newPassword"]
    confirmed = request.form["confirmPassword"]

    try:
        # Confirm user_name exists
        query = "SELECT * FROM users WHERE username = ?"
        res = c.execute(query, (user_name,))
        password_record = res.fetchone()
        
        if password_record:
            old_pass_hash = password_record[3]  # Assuming password is in the 4th column (index 3)
            
            if bcrypt.checkpw(old_pass.encode("utf-8"), old_pass_hash):
                if new_pass == confirmed and len(new_pass) > 0 and len(confirmed) > 0:
                    new_pass_hash = bcrypt.hashpw(new_pass.encode("utf-8"), bcrypt.gensalt())
                    update_query = "UPDATE users SET password = ? WHERE username = ?"
                    c.execute(update_query, (new_pass_hash, user_name))
                    conn.commit()
                    return render_template("login_sec.html")
                else:
                    # Return a generic error message for password mismatch
                    return redirect(url_for('changePass_sec_page', error='Passwords do not match or are empty'))
            else:
                # Return a generic error message for old password mismatch
                return redirect(url_for('changePass_sec_page', error='Old password is incorrect'))
        else:
            # Return a generic error message for non-existent user
            return redirect(url_for('changePass_sec_page', error='User does not exist'))
    except Exception as e:
        # Log the exception internally (not shown here)
        return redirect(url_for('changePass_sec_page', error='An unexpected error occurred'))
    finally:
        conn.close()


    

@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        name = request.form["name"]
        password = request.form["password"]

        conn = sqlite3.connect("database/shop_sec.db")
        c = conn.cursor()
        res = c.execute("SELECT * FROM users WHERE username=?", (name,))
        data = res.fetchone()
        conn.close()
        
        if data is not None:
            if bcrypt.checkpw(password.encode("utf-8"), data[3]):
                session['user_id'].append(data[0])
                return redirect(url_for('index'))
            else:
                flash('Incorrect Password', "erro")
                return redirect(url_for('login_page'))
        else:
            flash("Username or password incorrect!", "error")
            return redirect(url_for('login_page'))
    else:
        return render_template("login_page_sec.html")
        

    
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        name = request.form["name"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if email == '':
            flash("Email can't be empty!", "error")
            return redirect("/register")
        if name == '':
            flash("Name can't be empty!", "error")
            return redirect("/register")
        if password == '':
            flash("Password can't be empty!", "error")
            return redirect("/register")
        if password != confirm_password:
            flash("Password do not match!", "error")
            return redirect("/register")
        conn = sqlite3.connect("database/shop_sec.db")
        
        c = conn.cursor()
        print("ENTREI ATE AQUI2")
        print(name)
        print(email)
        c.execute("SELECT * FROM users WHERE username=? OR email=?", (name, email,))
        
        user = c.fetchone()
        
        if user is not None:
            if user[1] == name:
                flash('name already exists', "erro")
                return redirect(url_for('register_page'))
            else:
                flash('email already exists', "erro")
            return redirect(url_for('register_page'))
        else:
            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            c.execute("INSERT INTO users (email,username,password) VALUES (?, ?,?)", (email, name, password_hash))
            conn.commit()
            conn.close()
            return redirect(url_for('login_page'))
    else:
        print("Error in register")
        return render_template("register.html")
    
import sqlite3

def is_user_authorized_to_comment(title, user_id):
    # Connect to the database
    conn = sqlite3.connect("database/shop_sec.db")
    c = conn.cursor()
    
    # Execute the query to select all columns from the posts table
    c.execute("SELECT * FROM posts")
    
    # Fetch all results
    all_posts = c.fetchall()
    

    # Close the database connection
    conn.close()

    # Check if any post's title matches the provided title
    for post in all_posts:
        if post[1] == title:  # Assuming the title is in the second column
            return True
    
    # Return False if no matching title is found
    return False



    
@app.route("/submit_comment", methods=["POST"])
def submit_comment():
    if 'user_id' in session:
        comment_text = bleach.clean(request.form['comment_text'])
        post_id = request.form['product_id']
        if not is_user_authorized_to_comment(post_id, get_current_user_id()):
            flash('You are not authorized to comment on this post', "error")
            return redirect(url_for('index'))
        
        # c.execute("INSERT INTO comments (post_id, user_id, user_comment) VALUES (?, ?, ?)", (post_id, user_id, comment_text))
        conn = sqlite3.connect("database/shop_sec.db")
        c = conn.cursor()
        query = f'SELECT username FROM users WHERE user_id=?'
        res = c.execute(query, str(get_current_user_id()))
        user_name = res.fetchone()[0]

        c.execute("INSERT INTO comments (post_id, user_name, user_comment) VALUES(?,?,?)", (post_id, user_name, comment_text))
        conn.commit()
        conn.close()
        return redirect(url_for('checkOut', index=post_id))
    else:
        flash('Must loggin to comment', "erro")
        return redirect(url_for('login_page'))
    

    
#function to retriver the id of the current user    
app.route('/current_user_id')
def get_current_user_id():
    if 'user_id' in session and session['user_id']!= []:
        return session['user_id'][-1]
    else:
        return 'No user logged in'

#Erro handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template("Error/404.html", error_code=404), 404

@app.errorhandler(Exception)
def internal_server_error(error):
    return render_template("Error/500.html", error_code=500), 500

#Section for clear session data in case 
def shutdown(signum, frame):
    clear_session_data()
    print("Shutting down gracefully...")
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

def clear_session_data():
    # Delete session data files in the specified directory
    session_dir = app.config['SESSION_FILE_DIR']
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir)  
    else:
        print(f"Session data directory does not exist: {session_dir}")   

if __name__ == '__main__':
    app.run(debug=True)
