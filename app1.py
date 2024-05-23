# Import required libraries
from flask import Flask, render_template, request, redirect, url_for, g, session, flash
import sqlite3
import bcrypt
import requests
import os

app = Flask(__name__)
app.secret_key = 'SectetKey'

# Custom filter to zip two lists together
def zip_lists(a, b):
    return zip(a, b)

# Add the custom filter to Jinja2 environment
app.jinja_env.filters['zip_lists'] = zip_lists

# Function to get a connection to the SQLite database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('news_aggregator.db')
        g.db.row_factory = sqlite3.Row
    return g.db

# Function to close the database connection
@app.teardown_appcontext
def close_db(error):
    if 'db' in g:
        g.db.close()

# Function to initialize database
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.executescript(f.read())
        db.commit()

def init_db_and_files():
    init_db()
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        source TEXT,
        user_id INTEGER,
        edit_count INTEGER DEFAULT 0,
        featured INTEGER DEFAULT 0,
        category_id INTEGER
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        url TEXT UNIQUE
    )
    ''')
    conn.commit()
    conn.close()

# Function to check if user is logged in
def is_logged_in():
    return 'username' in session

# Function to fetch top headlines from News API
def get_top_headlines(api_key):
    url = 'https://newsapi.org/v2/top-headlines'
    params = {
        'apiKey': api_key,
        'country': 'IN'  # Country code as per ISO 3166-1 alpha-2
    }
    response = requests.get(url, params=params)
    data = response.json()
    if data['status'] == 'ok':
        return data['articles']
    else:
        return None

# Function to save user data to the database
def save_user_to_database(username, hashed_password):
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

# Function to save article data to the database
def save_article_to_database(title, content, source, user_id):
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("INSERT INTO articles (title, content, source, user_id) VALUES (?, ?, ?, ?)", (title, content, source, user_id))
    conn.commit()
    conn.close()

# Function to update article data in the database
def update_article_in_database(article_id, title, content, source, user_id, edit_count):
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("UPDATE articles SET title = ?, content = ?, source = ?, edit_count = edit_count + 1 WHERE id = ?", (title, content, source, article_id))
    conn.commit()
    conn.close()

##########################################################################
# Home route
@app.route('/')
def index():
    api_key = 'fbe4e4dc0f944629b23db0c5f03a210b'
    headlines = get_top_headlines(api_key)
    if headlines:
        username = session.get('username') if session.get('username') else None
        return render_template('index.html', headlines=headlines)
    else:
        return "Failed to fetch top headlines."

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('login_signup.html')  # Use login_signup.html

        # Check if username already exists
        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = c.fetchone()
        conn.close()

        if existing_user:
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('login_signup.html')

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Save user to database
        save_user_to_database(username, hashed_password)
        flash('You have successfully signed up! Please log in.', 'success')

        # Redirect to login page after successful signup
        return redirect(url_for('login'))

    # If GET request, render the signup form
    return render_template('login_signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']

        # Check if user exists in the database
        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user:
            # Check if the password is correct
            if bcrypt.checkpw(password.encode('utf-8'), user[2]):
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('Username does not exist. Please sign up.', 'danger')

    # If GET request, render the login form
    return render_template('login_signup.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# Add article route
@app.route('/create_article', methods=['GET', 'POST'])
def create_article():
    if 'username' not in session:
        flash('Please log in to add an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("SELECT id, name FROM categories")
    categories = c.fetchall()
    conn.close()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category_id = request.form['category_id']

        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()

        # Insert the new article into the database
        c.execute("INSERT INTO articles (title, content, category_id) VALUES (?, ?, ?)", 
                  (title, content, category_id))
        conn.commit()
        conn.close()

        flash('Article added successfully!', 'success')
        return redirect(url_for('view_articles'))

    return render_template('add_article.html', categories=categories)



# Article details route
@app.route('/article/<int:article_id>')
def article_details(article_id):
    # Fetch the article from the database
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
    article = c.fetchone()
    conn.close()

    if article:
        return render_template('article_details.html', article=article)
    else:
        flash('Article not found.', 'danger')
        return redirect(url_for('index'))

# Edit article route
@app.route('/edit_article/<int:article_id>', methods=['GET', 'POST'])
def edit_article(article_id):
    if 'username' not in session:
        flash('Please log in to edit an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    if request.method == 'POST':
        # Get form data
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']

        # Update the article in the database
        c.execute("UPDATE articles SET title = ?, content = ?, category = ? WHERE id = ?", 
                  (title, content, category, article_id))
        conn.commit()
        conn.close()

        flash('Article updated successfully!', 'success')
        return redirect(url_for('article_details', article_id=article_id))

    # If GET request, fetch the article to be edited
    c.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
    article = c.fetchone()
    conn.close()

    if article:
        return render_template('edit_article.html', article=article)
    else:
        flash('Article not found.', 'danger')
        return redirect(url_for('index'))

# Delete article route
@app.route('/delete_article/<int:article_id>', methods=['POST'])
def delete_article(article_id):
    if 'username' not in session:
        flash('Please log in to delete an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Delete the article from the database
    c.execute("DELETE FROM articles WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()

    flash('Article deleted successfully!', 'success')
    return redirect(url_for('index'))


# View profile route
@app.route('/profile')
def profile():
    if 'username' not in session:
        flash('Please log in to view your profile.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Fetch the user's details from the database
    c.execute("SELECT username, email FROM users WHERE username = ?", (session['username'],))
    user = c.fetchone()
    conn.close()

    if user:
        return render_template('profile.html', user=user)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))

# Change password route
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash('Please log in to change your password.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()

        # Fetch the current user's password from the database
        c.execute("SELECT password FROM users WHERE username = ?", (session['username'],))
        user = c.fetchone()

        if user and check_password_hash(user[0], current_password):
            if new_password == confirm_new_password:
                # Update the user's password in the database
                hashed_new_password = generate_password_hash(new_password)
                c.execute("UPDATE users SET password = ? WHERE username = ?", 
                          (hashed_new_password, session['username']))
                conn.commit()
                conn.close()

                flash('Password changed successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('New passwords do not match.', 'danger')
        else:
            flash('Current password is incorrect.', 'danger')

        conn.close()

    return render_template('change_password.html')


# Add news source route
@app.route('/add_source', methods=['GET', 'POST'])
def add_source():
    if 'username' not in session:
        flash('Please log in to add a news source.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        source_name = request.form['source_name']
        source_url = request.form['source_url']

        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()

        # Check if the source already exists
        c.execute("SELECT * FROM sources WHERE url = ?", (source_url,))
        existing_source = c.fetchone()

        if existing_source:
            flash('This news source is already in the database.', 'warning')
        else:
            # Insert the new source into the database
            c.execute("INSERT INTO sources (name, url) VALUES (?, ?)", (source_name, source_url))
            conn.commit()
            flash('News source added successfully!', 'success')

        conn.close()
        return redirect(url_for('index'))

    return render_template('add_source.html')

# Delete news source route
@app.route('/delete_source/<int:source_id>', methods=['POST'])
def delete_source(source_id):
    if 'username' not in session:
        flash('Please log in to delete a news source.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Delete the source from the database
    c.execute("DELETE FROM sources WHERE id = ?", (source_id,))
    conn.commit()
    conn.close()

    flash('News source deleted successfully!', 'success')
    return redirect(url_for('index'))


# View all news sources route
@app.route('/view_sources')
def view_sources():
    if 'username' not in session:
        flash('Please log in to view news sources.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Retrieve all news sources from the database
    c.execute("SELECT id, name, url FROM sources")
    sources = c.fetchall()
    conn.close()

    return render_template('view_sources.html', sources=sources)

# Edit news source route
@app.route('/edit_source/<int:source_id>', methods=['GET', 'POST'])
def edit_source(source_id):
    if 'username' not in session:
        flash('Please log in to edit a news source.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Retrieve the news source to be edited
    c.execute("SELECT name, url FROM sources WHERE id = ?", (source_id,))
    source = c.fetchone()

    if request.method == 'POST':
        new_name = request.form['source_name']
        new_url = request.form['source_url']

        # Update the news source in the database
        c.execute("UPDATE sources SET name = ?, url = ? WHERE id = ?", (new_name, new_url, source_id))
        conn.commit()
        conn.close()

        flash('News source updated successfully!', 'success')
        return redirect(url_for('view_sources'))

    conn.close()
    return render_template('edit_source.html', source=source)


# Add a new category route
@app.route('/add_category', methods=['GET', 'POST'])
def add_category():
    if 'username' not in session:
        flash('Please log in to add a category.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        category_name = request.form['category_name']

        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()

        # Insert the new category into the database
        c.execute("INSERT INTO categories (name) VALUES (?)", (category_name,))
        conn.commit()
        conn.close()

        flash('Category added successfully!', 'success')
        return redirect(url_for('view_categories'))

    return render_template('add_category.html')

# View all categories route
@app.route('/view_categories')
def view_categories():
    if 'username' not in session:
        flash('Please log in to view categories.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Retrieve all categories from the database
    c.execute("SELECT id, name FROM categories")
    categories = c.fetchall()
    conn.close()

    return render_template('view_categories.html', categories=categories)


# Add a news article route
@app.route('/add_article', methods=['GET', 'POST'])
def add_article():
    if 'username' not in session:
        flash('Please log in to add an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("SELECT id, name FROM categories")
    categories = c.fetchall()
    conn.close()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category_id = request.form['category_id']

        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()

        # Insert the new article into the database
        c.execute("INSERT INTO articles (title, content, category_id) VALUES (?, ?, ?)", 
                  (title, content, category_id))
        conn.commit()
        conn.close()

        flash('Article added successfully!', 'success')
        return redirect(url_for('view_articles'))

    return render_template('add_article.html', categories=categories)



# View all articles route
@app.route('/view_articles')
def view_articles():
    if 'username' not in session:
        flash('Please log in to view articles.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Retrieve all articles from the database
    c.execute("""
        SELECT articles.id, articles.title, articles.content, categories.name 
        FROM articles 
        JOIN categories ON articles.category_id = categories.id
    """)
    articles = c.fetchall()
    conn.close()

    return render_template('view_articles.html', articles=articles)


# Edit an existing article route
@app.route('/edit_article/<int:article_id>', methods=['GET', 'POST'])
def edit_article_details(article_id):
    if 'username' not in session:
        flash('Please log in to edit an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    if request.method == 'POST':
        # Get form data
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']

        # Update the article in the database
        c.execute("UPDATE articles SET title = ?, content = ?, category = ? WHERE id = ?", 
                  (title, content, category, article_id))
        conn.commit()
        conn.close()

        flash('Article updated successfully!', 'success')
        return redirect(url_for('article_details', article_id=article_id))

    # If GET request, fetch the article to be edited
    c.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
    article = c.fetchone()
    conn.close()

    if article:
        return render_template('edit_article.html', article=article)
    else:
        flash('Article not found.', 'danger')
        return redirect(url_for('index'))

# Delete an existing article route
@app.route('/delete_article/<int:article_id>', methods=['POST'])
def delete_article_details(article_id):
    if 'username' not in session:
        flash('Please log in to delete an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Delete the article from the database
    c.execute("DELETE FROM articles WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()

    flash('Article deleted successfully!', 'success')
    return redirect(url_for('view_articles'))

# Mark article as featured route
@app.route('/feature_article/<int:article_id>', methods=['POST'])
def feature_article(article_id):
    if 'username' not in session:
        flash('Please log in to feature an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Update the article to mark it as featured
    c.execute("UPDATE articles SET featured = 1 WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()

    flash('Article marked as featured!', 'success')
    return redirect(url_for('view_articles'))

# Unmark article as featured route
@app.route('/unfeature_article/<int:article_id>', methods=['POST'])
def unfeature_article(article_id):
    if 'username' not in session:
        flash('Please log in to unfeature an article.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()

    # Update the article to unmark it as featured
    c.execute("UPDATE articles SET featured = 0 WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()

    flash('Article unmarked as featured!', 'success')
    return redirect(url_for('view_articles'))

# Route for searching articles
@app.route('/search', methods=['GET', 'POST'])
def search_articles():
    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM articles WHERE title LIKE ? OR content LIKE ?", ('%' + search_query + '%', '%' + search_query + '%'))
        search_results = cursor.fetchall()
        conn.close()
        return render_template('search_results.html', search_results=search_results, search_query=search_query)
    else:
        return redirect(url_for('index'))

# Route for handling error 404
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

# Route for handling error 500
@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

# Route for handling internal server errors
@app.route('/internal_error')
def internal_error():
    # Simulate an internal server error
    return 1 / 0

##########################################################################

if __name__ == '__main__':
    try:
        init_db_and_files()
        app.run(debug=True)
    except Exception as e:
        print(f"Error running the Flask app: {e}")
