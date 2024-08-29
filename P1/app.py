from datetime import timedelta
from flask import Flask,Blueprint, render_template, session, redirect, request, url_for, flash, send_from_directory
import sqlite3
import os
from flask_session import Session
import signal
import sys     

app = Flask(__name__)

# Set the secret key directly
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'unsafe_version')

SERVER_PATH = os.path.dirname(os.path.abspath(__file__))
DB_STRING = os.path.join(SERVER_PATH, 'database/shop.db')
public_path = os.path.join(os.path.dirname(__file__), 'public')

app.template_folder = public_path

# Initialize the Flask-Session extension
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_unsafe_session/data'
app.permanent_session_lifetime = timedelta(days=365)
Session(app)


@app.route('/')
def home():
    return redirect(url_for('index'))

@app.route("/index_page")
def index():
    if ('user_id' in session) and (session['user_id'] != []):
        conn = sqlite3.connect("database/shop.db")
        c = conn.cursor()
        query = f'SELECT username FROM users WHERE user_id=?'
        res = c.execute(query, str(get_current_user_id()))
        user_name = res.fetchone()[0]
    
        return render_template("index.html", user_name=user_name)
    else:
        return render_template("index.html", user_name=None)
    
@app.route("/login_page")
def login_page():
    return render_template("login.html")

@app.route("/register_page")
def register_page():
    return render_template("register.html")

@app.route("/logout")
def logout():
    return redirect("/login_page")

@app.route("/checkOut")
def checkOut():
    index = request.args.get('index')
    conn = sqlite3.connect("database/shop.db")  # Replace with your actual database file
    cursor = conn.cursor()
    cursor.execute(f'SELECT user_name, user_comment FROM comments WHERE post_id="{index}"')
    comments = cursor.fetchall()
    conn.close()
    
    return render_template("checkOut.html", keys=index, comments=comments)

@app.route("/change_pass_page")
def changePass_page():
    error_message = request.args.get('error')

    if error_message:
        return render_template('change_pass.html', error=error_message)
    return render_template("change_pass.html")

@app.route("/change_pass", methods=["POST"])
def change_pass():
    conn = sqlite3.connect('database/shop.db')
    c = conn.cursor()
    user_name = request.form["user_name"]
    new_pass = request.form["newPassword"]
    confirmed = request.form["confirmPassword"]

    try:
        # Confirm user_name exists
        query = f"SELECT * FROM users WHERE username = ?"
        c.execute(query, (user_name,))
        name_exists = c.fetchone()

        if new_pass == confirmed and name_exists:
            update_query = f"UPDATE users SET password = ? WHERE username = ?"
            c.execute(update_query, (new_pass, user_name))
            conn.commit()
            return render_template("login.html")
        else:
            if not(name_exists):
                return redirect(url_for("changePass_page", error='User does not exist'))
            return redirect(url_for("changePass_page", error='Passwords do not match'))
    except Exception as e:
        return f"An error occurred: {str(e)}"

    
@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        name = request.form["name"]
        password = request.form["password"]

        conn = sqlite3.connect("database/shop.db")
        c = conn.cursor()
        res = c.execute(f'SELECT 1 FROM users WHERE username="{name}" AND password="{password}"')
        data = res.fetchall()
        
        if data == []:
            flash("Username or password incorrect!", "error")
            return redirect("/login_page")
        else:
            res = c.execute(f'SELECT user_id FROM users WHERE username="{name}" AND password="{password}"')
            id = res.fetchone()[0]
            session['user_id'].append(id)
            c.close()
            return redirect(url_for('index'))
    else:
        render_template("index.html")


    
@app.route("/register", methods=["GET", "POST"])
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
        
        conn = sqlite3.connect("database/shop.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND email=?", (name,email,))
        user = c.fetchone()

        if user is not None:
            if user[1] == name:
                flash('name already exists', "erro")
                return redirect(url_for('register_page'))
            else:
                flash('email already exists', "erro")
            return redirect(url_for('register_page'))
        else:
            #insiro na base de dados
            c.execute("INSERT INTO users (email,username,password) VALUES (?, ?,?)", (email, name, password))

            conn.commit()
            conn.close()
            
            if (is_folder_empty(app.config['SESSION_FILE_DIR'])):
                session['user_id']=[]
            else:
                query = f'SELECT user_id FROM users WHERE user_id=?'
                res = c.execute(query, str(get_current_user_id()))
                user_id = res.fetchone()[0]
                session['user_id'].append(user_id)
            return redirect(url_for('login_page'))
    else:
        print("Error in register")
        return render_template("register.html")
    
@app.route("/submit_comment", methods=["POST"])
def submit_comment():
    if 'user_id' in session:
        comment_text = request.form['comment_text']
        post_id = request.form['product_id']
        
        # c.execute("INSERT INTO comments (post_id, user_id, user_comment) VALUES (?, ?, ?)", (post_id, user_id, comment_text))
        conn = sqlite3.connect("database/shop.db")
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

    

app.route('/current_user_id')
def get_current_user_id():
    if (type(session['user_id']) is list):
        return session['user_id'][-1]
    else:
        return session['user_id']
    

def is_folder_empty(folder_path):
    # Use os.listdir() to get a list of all items (files and subfolders) in the folder
    items = os.listdir(folder_path)
    
    # Check if there are any items in the list
    return len(items) < 3

if __name__ == '__main__':
    app.run(debug=True)
