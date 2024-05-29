# Import required libraries
from flask import Flask, render_template, request, redirect, url_for, g, session
from flask_wtf import csrf
import sqlite3
import bcrypt
import requests
import json
import os
import secrets
from werkzeug.security import check_password_hash
from flask import flash, get_flashed_messages



app = Flask(__name__)
app.secret_key = 'SectetKey'

# Function to get the database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('news_aggregator.db')
    return db


# Custom filter to zip two lists together
def zip_lists(a, b):
    return zip(a, b)

# Add the custom filter to Jinja2 environment
app.jinja_env.filters['zip_lists'] = zip_lists

# Function to get a connection to the SQLite database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('news_aggregator.db')
        g.db.row_factory = sqlite3.Row  # Set row factory to sqlite3.Row
    return g.db

# Function to close the database connection
@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Function to initialize database
def init_db():
    with app.app_context():
        conn = get_db()
        c = conn.cursor()
        
        # Drop the existing 'users' table if it exists
        c.execute('''DROP TABLE IF EXISTS users''')
        
        # Create a new 'users' table with the required columns
        c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            mobile_number TEXT,
            username TEXT UNIQUE,
            password TEXT,
            confirm_password TEXT
        )
        ''')
        
        # Create the 'articles' table if it doesn't exist
        c.execute('''
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            source TEXT,
            user_id INTEGER,
            edit_count INTEGER DEFAULT 0,
            files BLOB
        )
        ''')
        
        # Commit the changes to the database
        conn.commit()
        
        

# Call the init_db() function to create tables if they don't exist
init_db()

# Function to check if user or admin is logged in
def is_logged_in():
    return session.get('logged_in')

def is_admin():
    return session.get('is_admin')

# Function to fetch top headlines from News API
def get_top_headlines(api_key, selected_country, page_size=10, page_number=1):
    url = 'https://newsapi.org/v2/top-headlines'
    params = {
        'apiKey': api_key,
        'country': selected_country,  # Use the selected country parameter here
        'pageSize': page_size,
        'page': page_number
    }
    response = requests.get(url, params=params)
    data = response.json()
    if data['status'] == 'ok':
        return data['articles']
    else:
        return None

def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

# Function to save user data to the database
def save_user_to_database(name, email, mobile_number, username, hashed_password):
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (name, email, mobile_number, username, password) VALUES (?, ?, ?, ?, ?)",
              (name, email, mobile_number, username, hashed_password))
    conn.commit()
    conn.close()


# Function to save article data to the database
def save_article_to_database(title, content, source, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO articles (title, content, source, user_id) VALUES (?, ?, ?, ?)", (title, content, source, user_id))
    conn.commit()

# Function to update article data in the database
def update_article_in_database(article_id, title, content, source, user_id, edit_count, files=None):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE articles SET title = ?, content = ?, source = ?, edit_count = edit_count + 1, files = ? WHERE id = ?", (title, content, source, files, article_id))
    conn.commit()

# Homepage route
@app.route('/')
def index():
    api_key = 'fbe4e4dc0f944629b23db0c5f03a210b'
    selected_country = request.args.get('country', 'IN') 
    page_number = request.args.get('page', 1, type=int)  

    headlines = get_top_headlines(api_key, selected_country, page_number=page_number)

    if headlines:
        return render_template('index.html', headlines=headlines, page_number=page_number, country=selected_country)
    else:
        return "Failed to fetch top headlines."


# Admin Login route
@app.route('/admin_login', methods=['POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('admin_password')

        if username == 'SWEHUL' and password == 'ADMIN':
            session['username'] = username  # Set the username in the session
            flash('You have successfully logged in as admin!', 'success')
            return redirect(url_for('user_articles'))  # Redirect to admin_dashboard
        else:
            flash('Invalid admin credentials. Please try again.', 'danger')
    
    # If login fails or method is not POST, redirect back to the login page
    return redirect(url_for('login'))

# Route user_articles READ ARTICLES
@app.route('/user_articles')
def user_articles():
    if is_logged_in():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM articles")
        all_articles = cursor.fetchall()
        conn.close()
        
        if all_articles:
            csrf_token = generate_csrf()  # Generate CSRF token
            return render_template('user_articles.html', user_articles=all_articles, csrf_token=csrf_token)
        else:
            flash('No articles found.', 'info')
            csrf_token = generate_csrf()  # Generate CSRF token
            return render_template('user_articles.html', user_articles=[], csrf_token=csrf_token)
    else:
        flash('You need to login first to view your articles.', 'danger')
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        name = request.form['usrname']
        email = request.form['email']
        mobile_number = request.form['mobile_number']
        username = request.form['usrname']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('login_signup.html')

        # Check if username or email already exists
        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = c.fetchone()
        conn.close()

        if existing_user:
            if existing_user[3] == username:
                flash('Username already exists. Please choose another.', 'danger')
            elif existing_user[2] == email:
                flash('Email already registered. Please use another email or log in.', 'danger')
            return render_template('login_signup.html')

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Save user to database
        try:
            save_user_to_database(name, email, mobile_number, username, hashed_password)
            flash('You have successfully signed up! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if 'UNIQUE constraint failed: users.email' in str(e):
                flash('Email already registered. Please use another email or log in.', 'danger')
            elif 'UNIQUE constraint failed: users.username' in str(e):
                flash('Username already exists. Please choose another.', 'danger')
            else:
                flash('An error occurred. Please try again.', 'danger')
            return render_template('login_signup.html')

    else:
        # Render signup form
        return render_template('signup_form.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username_or_email = request.form['username_or_email']
        password = request.form['password']

        # Check if user exists
        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()
        # Check if the username_or_email matches either username or email
        c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[5]):
            # Set session variables
            session['logged_in'] = True
            session['username'] = user[3]  # Username
            session['user_id'] = user[0]

            flash('You have successfully logged in!', 'success')

            # Redirect to Read Articles Page after successful login
            return redirect(url_for('user_articles'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    # If GET request or login fails, render the login form
    return render_template('login_signup.html')


@app.route('/changepass', methods=['POST'])
def changepass():
    # Your view logic here
    pass

#Forgot Password
@app.route('/forgotpass', methods=['POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['femail']

        # Check if user exists
        user = User.query.filter_by(email=email).first()

        if user:
            # Send email with password reset instructions
            flash('Password reset instructions sent to your email.')
        else:
            flash('User with this email does not exist.')

        return redirect('/')


# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# SwehulYoutube route
@app.route('/SwehulYoutube')
def swehul_youtube():
    # Render the SwehulYoutube.html template
    return render_template('SwehulYoutube.html')

# Article Detail Page route
@app.route('/article/<int:article_id>')
def article_detail(article_id):
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
    article = c.fetchone()
    conn.close()
    
    if article:
        return render_template('article_detail.html', article=article)
    else:
        return "Article not found."

# Articles route
@app.route('/articles', methods=['GET', 'POST'])
def articles():
    if is_logged_in():
        if request.method == 'POST':
            # Form data received, save or update the article in the database
            title = request.form['title']
            content = request.form['content']
            source = request.form['source']
            user_id = session.get('user_id')
            article_id = request.form.get('article_id')
            old_files = request.form.get('old_files')  # Retrieve old files from form

            if article_id:
                # Update existing article
                edit_count = int(request.form.get('edit_count', 0))
                update_article_in_database(int(article_id), title, content, source, user_id, edit_count)
                flash('Article updated successfully!','success')
            else:
                # Save new article
                save_article_to_database(title, content, source, user_id)
                flash('Article submitted successfully!','success')

            # Redirect to user_articles page after submitting or updating article
            return redirect(url_for('user_articles'))
        else:
            # Check if old content is passed along with the redirect
            old_title = request.args.get('title')
            old_source = request.args.get('source')
            old_article_id = request.args.get('article_id')  # Retrieve old_article_id from query parameters
            old_edit_count = int(request.args.get('edit_count', 0))
            old_files = request.args.get('old_files')  # Retrieve old files from query parameters

            # Render the articles page with the form to submit or edit articles
            return render_template('articles.html', username=session['username'], old_title=old_title, old_source=old_source, old_article_id=old_article_id, old_edit_count=old_edit_count, old_files=old_files if old_files else '', article_id=old_article_id)
    else:
        flash('You need to login first to view articles.', 'danger')
        return redirect(url_for('login'))


# Route for handling article submission
@app.route('/submit_article', methods=['POST'])
def submit_article():
    if request.method == 'POST':
        # Form data retrieve karein
        title = request.form['title']
        content = request.form['content']
        source = request.form['source']
        user_id = session.get('user_id')
        files = request.files.getlist('files')  # Retrieve files from form

        if user_id:
            #Save Article  In Database  
            save_article_to_database(title, content, source, user_id, files=files)
            flash('Article submitted successfully!', 'success')
            # redirect to user_articles route after submit Article
            return redirect(url_for('user_articles'))
        else:
            flash('User ID not found in session. Please log in again.', 'danger')
            return redirect(url_for('login'))

# PersonalisedGenresSelection route
@app.route('/PersonalisedGenresSelection')
def personalised_genres_selection():
    # Render the PersonalisedGenresSelection.html template
    return render_template('PersonalisedGenresSelection.html')

# PersonalisedGenresSelection route
@app.route('/about')
def render_about_page():
    return render_template('about.html')

# Function to fetch articles from database
def fetch_articles_from_database():
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("SELECT * FROM articles")
    articles = c.fetchall()
    conn.close()
    return articles

# Updated is_admin function signature
def is_admin():
    return 'username' in session and session['username'] == 'SWEHUL'


# Function to check if a user is the author of a specific article
def is_author(article_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id FROM articles WHERE id = ?", (article_id,))
    result = c.fetchone()
    if result and result[0] == session.get('user_id'):
        return True
    return False

# Route for Deleting an article
@app.route('/delete_file/<int:article_id>/<path:file_name>', methods=['GET', 'POST'])
def delete_file(article_id, file_name):
    if is_logged_in():
        if is_admin() or is_author(article_id):
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM articles WHERE id =?", (article_id,))
            article = c.fetchone()
            if article:
                # Check if the file exists for the given article_id and file_name
                files = article['files'] if 'files' in article else ''
                file_list = files.split(',') if files else []
                if file_name in file_list:
                    # Remove the file name from the list of files
                    file_list.remove(file_name)
                    updated_files = ','.join(file_list)
                    # Update the article record with the new list of files
                    c.execute("UPDATE articles SET files =? WHERE id =?", (updated_files, article_id))
                    conn.commit()
                    conn.close()
                    flash(f'File {file_name} for article {article_id} deleted successfully','success')
                    return redirect(url_for('user_articles'))
                else:
                    flash(f'File {file_name} not found for article {article_id}', 'danger')
            else:
                flash(f'Article {article_id} not found', 'danger')
        else:
            flash('You are not authorized to delete this file.', 'danger')
    else:
        flash('You need to login first to delete files.', 'danger')
    return redirect(url_for('user_articles'))

# Route for Editing An Article
@app.route('/edit_article/<int:article_id>', methods=['GET', 'POST'])
def edit_article(article_id):
    if is_logged_in():
        if is_admin() or is_author(article_id):
            if request.method == 'POST':
                # Handle form data
                title = request.form['title']
                content = request.form['content']
                source = request.form['source']
                user_id = session.get('user_id')

                if user_id:
                    # Update the article
                    edit_count = int(request.form.get('edit_count', 0))
                    update_article_in_database(article_id, title, content, source, user_id, edit_count)
                    flash('Article updated successfully!', 'success')

                    # Redirect user to articles page after updating article
                    return redirect(url_for('user_articles'))
                else:
                    flash('User ID not found in session. Please log in again.', 'danger')
                    return redirect(url_for('login'))
            else:
                # Fetch the old content of the article from the database
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
                article = c.fetchone()
                
                if article:
                    # Convert old_files to string explicitly
                    old_files = str(article[4]) if article[4] is not None else ''
                    # Render the edit article page with old content pre-filled in the form
                    return render_template('articles.html', username=session['username'], old_title=article[1], old_content=article[2], old_source=article[3], old_files=old_files, old_article_id=article[0], edit_count=article[5])
                else:
                    flash('Article not found.', 'danger')
                    return redirect(url_for('user_articles'))
        else:
            flash('You are not authorized to edit this article.', 'danger')
            return redirect(url_for('user_articles'))
    else:
        flash('You need to login first to edit articles.', 'danger')
        return redirect(url_for('login'))

# Function to update article data in the database
def update_article_in_database(article_id, title, content, source, user_id, edit_count):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE articles SET title = ?, content = ?, source = ?, user_id = ?, edit_count = ? WHERE id = ?", (title, content, source, user_id, edit_count, article_id))
    conn.commit()

# Function to save data to SQLite database and JSON file
def save_data_to_files(data, filename):
    # Save data to SQLite database
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    for article in data:
        if isinstance(article, dict):
            c.execute("INSERT OR REPLACE INTO articles (id, title, content, source, user_id, edit_count) VALUES (?, ?, ?, ?, ?, ?)",
                      (article['id'], article['title'], article['content'], article['source'], article['user_id'], article.get('edit_count', 0)))
    conn.commit()
    conn.close()

    # Transform database rows into a list of dictionaries
    json_data = []
    for article in data:
        if isinstance(article, dict):
            json_data.append({
                'id': article['id'],
                'title': article['title'],
                'content': article['content'],
                'source': article['source'],
                'user_id': article['user_id'],
                'edit_count': article.get('edit_count', None)
            })

    # Save data to JSON file
    with open(filename, 'w') as f:
        json.dump(json_data, f, indent=2)

# Function to initialize database and JSON file
def init_db_and_files():
    init_db()
    articles = fetch_articles_from_database()
    save_data_to_files(articles, 'articles.json')

# Get the directory path of the current script (app.py)
script_dir = os.path.dirname(__file__)
file_path = os.path.join(script_dir, "articles.json")

# Function to fetch articles from JSON file
def fetch_articles_from_json(filename):
    try:
        print(f"Trying to open JSON file: {filename}")
        with open(filename, 'r') as f:
            print("File opened successfully")
            data = json.load(f)
        print("Data loaded successfully")
        return data
    except FileNotFoundError:
        print("File not found")
        return []
    

###############################
# Route to view records in a table
@app.route('/view_table/<table_name>')
def view_table(table_name):
    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    fields = [info[1] for info in cursor.fetchall()]
    cursor.execute(f"SELECT rowid, * FROM {table_name}")
    records = cursor.fetchall()
    conn.close()
    return render_template('AdminDBManage.html', table_name=table_name, fields=fields, records=records, section='view')

# Admin Dashboard route
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session['username'] == 'SWEHUL':
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM articles")
        articles = cursor.fetchall()
        conn.close()

        # Assuming you have the table_name and record_id available
        table_name = "your_table_name"  # Replace with actual table name
        record_id = 123  # Replace with actual record ID

        return render_template('AdminDBManage.html', articles=articles, table_name=table_name, record_id=record_id)
    else:
        flash('You need to log in as admin to access the dashboard.', 'danger')
        return redirect(url_for('login'))


# add_record route
@app.route('/admin_dashboard/add/<table_name>', methods=['GET', 'POST'])
def add_record(table_name):
    if 'username' in session and session['username'] == 'SWEHUL':
        if request.method == 'POST':
            # Retrieve form data and insert into the specified table
            conn = get_db()
            cursor = conn.cursor()
            column_names = request.form.getlist('column_name')
            column_values = request.form.getlist('column_value')
            placeholders = ', '.join(['?'] * len(column_values))
            cursor.execute(f"INSERT INTO {table_name} ({', '.join(column_names)}) VALUES ({placeholders})", column_values)
            conn.commit()
            conn.close()
            flash('Record added successfully!', 'success')
            return redirect(url_for('view_table_data', table_name=table_name))
        else:
            # Fetch table columns to render the form
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            conn.close()
            return render_template('AddRecord.html', table_name=table_name, columns=columns)
    else:
        flash('You need to log in as admin to access the dashboard.', 'danger')
        return redirect(url_for('login'))

# Route to edit an article
@app.route('/admin_dashboard/edit/<table_name>/<int:record_id>', methods=['GET', 'POST'])
def edit_record(table_name, record_id):
    if 'username' in session and session['username'] == 'SWEHUL':
        if request.method == 'POST':
            # Retrieve form data and update the record in the specified table
            conn = get_db()
            cursor = conn.cursor()
            column_names = request.form.getlist('column_name')
            column_values = request.form.getlist('column_value')
            update_query = ', '.join([f"{column_name} = ?" for column_name in column_names])
            cursor.execute(f"UPDATE {table_name} SET {update_query} WHERE id = ?", column_values + [record_id])
            conn.commit()
            conn.close()
            flash('Record updated successfully!', 'success')
            return redirect(url_for('view_table_data', table_name=table_name))
        else:
            # Fetch the record from the specified table to pre-fill the form
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name} WHERE id = ?", (record_id,))
            record = cursor.fetchone()
            column_names = [description[0] for description in cursor.description]
            conn.close()

            # Check if the current user is the author of the record or an admin
            if session['username'] == 'SWEHUL' or record['user_id'] == session.get('user_id'):
                return render_template('EditRecord.html', table_name=table_name, record=record, column_names=column_names, record_id=record_id)
            else:
                flash('You are not authorized to edit this record.', 'danger')
                return redirect(url_for('view_table_data', table_name=table_name))
    else:
        flash('You need to log in as admin to access the dashboard.', 'danger')
        return redirect(url_for('login'))

# Route to delete an article
@app.route('/delete_article/<int:article_id>', methods=['POST'])
def delete_article(article_id):
    if 'username' in session:
        conn = get_db()
        cursor = conn.cursor()
        
        # Retrieve user_id from session
        user_id = session.get('user_id')
        
        # Check if the current user is the author of the article or an admin
        cursor.execute("SELECT user_id FROM articles WHERE id = ?", (article_id,))
        result = cursor.fetchone()
        article_user_id = result[0] if result else None
        
        if session['username'] == 'SWEHUL' or (article_user_id is not None and user_id == article_user_id):
            cursor.execute("DELETE FROM articles WHERE id = ?", (article_id,))
            conn.commit()
            conn.close()
            flash('Article deleted successfully!', 'success')
        else:
            flash('You are not authorized to delete this article.', 'danger')
        
        return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard or any appropriate page
    else:
        flash('You need to log in to delete articles.', 'danger')
        return redirect(url_for('login'))


# Route to display all users
@app.route('/admin/users')
def view_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template('AdminDBManage.html', tables=[], table_name='users', column_names=['id', 'username', 'email'], records=users, section='view')


# Route to display articles of a specific user
@app.route('/admin/user/articles/<int:user_id>')
def view_user_articles(user_id):
    if not is_admin():
        flash('You need to log in as admin first.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, content FROM articles WHERE user_id = ?", (user_id,))
    articles = cursor.fetchall()  # Make sure to fetch the 'id' attribute
    conn.close()

    return render_template('AdminDBManage.html', table_name='articles', column_names=['ID', 'Title', 'Content'], records=articles)


# Route to add a new article for a user
@app.route('/admin/user/add_article/<int:user_id>', methods=['GET', 'POST'])
def add_user_article(user_id):
    if not is_admin():
        flash('You need to log in as admin first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO articles (user_id, title, content) VALUES (?, ?, ?)", (user_id, title, content))
        conn.commit()
        conn.close()
        flash('Article added successfully!', 'success')
        return redirect(url_for('view_user_articles', user_id=user_id))

    return render_template('add_article.html', user_id=user_id)


# Route to edit an article of a user
@app.route('/admin/user/edit_article/<int:user_id>/<int:article_id>', methods=['GET', 'POST'])
def edit_user_article(user_id, article_id):
    if not is_admin():
        flash('You need to log in as admin first.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
    article = cursor.fetchone()

    # Accessing the 'id' column of the article
    article_id = article['id']


    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE articles SET title = ?, content = ? WHERE id = ?", (title, content, article_id))
        conn.commit()
        conn.close()
        flash('Article updated successfully!', 'success')
        return redirect(url_for('view_user_articles', user_id=user_id))

    return render_template('edit_article.html', user_id=user_id, article=article)


# Route to delete an article of a user
@app.route('/admin/user/delete_article/<int:user_id>/<int:article_id>', methods=['POST'])
def delete_user_article(user_id, article_id):
    if not is_admin():
        flash('You need to log in as admin first.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM articles WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()
    flash('Article deleted successfully!', 'success')
    return redirect(url_for('view_user_articles', user_id=user_id))

###################################################
@app.route('/AdminDBManage')
def admin_db_manage():
    # Function logic here
    return render_template('AdminDBManage.html')

@app.route('/show_database_data')
def show_database_data():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM articles")  # Change 'articles' to your table name
        data = cursor.fetchall()
        conn.close()
        
        if data:
            return render_template('AdminDBManage.html', data=data)
        else:
            return "No data found in the database."

    except Exception as e:
        return f"An error occurred: {str(e)}"


if __name__ == '__main__':
    try:
        init_db_and_files()
        app.run(debug=True)
    except Exception as e:
        print(f"Error running the Flask app: {e}")