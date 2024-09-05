import sqlite3

conn=sqlite3.connect('database/shop_sec.db');
c = conn.cursor();

# c.execute("DROP TABLE users")
# c.execute("DROP TABLE posts")
# c.execute("DROP TABLE comments")

#CRIADA TABLE USERS
c.execute("""CREATE TABLE users (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            two_factor TEXT 
            ) """)  


#CRIADA TABLE POSTS
c.execute("""CREATE TABLE posts (
            post_id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            name TEXT NOT NULL
            ) """)

#CRIADA TABLE COMMENTS
c.execute("""CREATE TABLE comments (
            post_id TEXT NOT NULL,
            user_id   INTEGER,
            user_name TEXT NOT NULL,
            user_comment TEXT NOT NULL
            ) """)

c.execute("""CREATE TABLE fileComments (
            post_id TEXT NOT NULL,
            user_id INTEGER,
            user_name TEXT NOT NULL,
            user_comment TEXT NOT NULL,
            file_name TEXT,              
            file_count INTEGER DEFAULT 0, 
            file_content BLOB 
            ) """)


    

#TESTER
# c.execute("SELECT user_id FROM users WHERE username='joao'")
# existing_user = c.fetchone()

# if existing_user is None:
#     c.execute("INSERT INTO users (username, email, password) VALUES ('joao', 'joao1@ua.pt', '123')")
# else:
#     print("User 'joao' already exists")
#c.execute("INSERT INTO users(username, firstname, lastname, pword) VALUES('Hugito', 'Hugo', 'D', 'pass2')")  
#c.execute("INSERT INTO users(username, firstname, lastname, pword) VALUES('Rager', 'Claudio', 'A', 'pass3')") 
#c.execute("INSERT INTO users(username, firstname, lastname, pword) VALUES('CSGod', 'André', 'C', 'pass4')")      

# c.execute("INSERT INTO posts(title, name) VALUES('/img/blog-1.jpg', 'hoodie')")
# c.execute("INSERT INTO posts(title, name) VALUES('/img/blog-2.jpg', 'Should I Ragequit?', '3')")   
# c.execute("INSERT INTO posts(title, name) VALUES('/img/blog-3.jpg', 'Nerf JuanDeag?', '4')")    

# c.execute("INSERT INTO comments(creator_id, posted_id, msg) VALUES('1', '4', 'Amazing')")
# c.execute("INSERT INTO comments(creator_id, posted_id, msg) VALUES('1', '4', 'Nvm just broke with my gf')")
# c.execute("INSERT INTO comments(creator_id, posted_id, msg) VALUES('2', '2', 'Never give up')")

# c.execute("SELECT * FROM comments WHERE posted_id='4' ")
# for row in c:
#     print('row = %r' % (row,))

conn.commit()
conn.close()