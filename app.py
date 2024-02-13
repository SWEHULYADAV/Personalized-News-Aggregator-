# Import required libraries
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Function to initialize database
def init_db():
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS articles 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, source TEXT, user_id INTEGER)''')
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
        'country': 'us'  # Country code as per ISO 3166-1 alpha-2
    }
    response = requests.get(url, params=params)
    data = response.json()
    if data['status'] == 'ok':
        return data['articles']
    else:
        return None

# Function to save user data to the database
def save_user_to_database(username, password):
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

# Function to save article data to the database
def save_article_to_database(title, content, source, user_id):
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("INSERT INTO articles (title, content, source, user_id) VALUES (?, ?, ?, ?)", (title, content, source, user_id))
    conn.commit()
    conn.close()

# Homepage route
@app.route('/')
def index():
    if is_logged_in():
        api_key = 'fbe4e4dc0f944629b23db0c5f03a210b'
        headlines = get_top_headlines(api_key)
        if headlines:
            return render_template('index.html', username=session['username'], headlines=headlines)
        else:
            return "Failed to fetch top headlines."
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login form submission
        username = request.form['username']
        password = request.form['password']
        # Placeholder authentication logic, replace with your actual logic
        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['username'] = username  # Set session variable
            session['user_id'] = user[0]  # Set user ID in session
            flash('You have successfully logged in!', 'success')
            return redirect(url_for('index'))  # Redirect to homepage after successful login
        else:
            # If login fails, render the login form again with an error message
            login_error = "Invalid username or password. Please try again."
            return render_template('login_signup.html', login_error=login_error)
    # If GET request, simply render the login form
    return render_template('login_signup.html', login_error=None)


# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Handle signup form submission
        username = request.form['username']
        password = request.form['password']
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Placeholder logic for saving user to database, replace with actual logic
        save_user_to_database(username, hashed_password.decode('utf-8'))  # Decode hashed_password before passing to the function
        flash('You have successfully signed up! Please log in.', 'success')
        # Redirect user to login page after successful signup
        return redirect(url_for('login'))
    # If GET request, simply render the signup form
    return render_template('signup.html')  # Assuming you have a signup.html template


# Logout route
@app.route('/logout')
def logout():
    # Logout logic here
    # For example, clearing session data
    session.clear()
    # Redirect to login page after logout
    return redirect(url_for('login'))

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
            # Form data received, save the article to database
            title = request.form['title']
            content = request.form['content']
            source = request.form['source']
            # Get user ID from session
            user_id = session.get('user_id')
            if user_id:
                save_article_to_database(title, content, source, user_id)
                flash('Article submitted successfully!', 'success')
                return redirect(url_for('articles'))  # Redirect to articles page after submitting article
            else:
                flash('User ID not found in session. Please log in again.', 'danger')
                return redirect(url_for('login'))
        else:
            # Render the articles page with the form to submit articles
            return render_template('articles.html', username=session['username'])
    else:
        flash('You need to login first to view articles.', 'danger')
        return redirect(url_for('login'))

# New route for handling article submission
@app.route('/submit_article', methods=['POST'])
def submit_article():
    if request.method == 'POST':
        # Retrieve data from the form
        title = request.form['title']
        content = request.form['content']
        source = request.form['source']
        # Get user ID from session
        user_id = session.get('user_id')
        if user_id:
            # Save article to the database
            save_article_to_database(title, content, source, user_id)
            flash('Article submitted successfully!', 'success')
            # Redirect to user_articles page after successfully submitting article
            return redirect(url_for('user_articles'))  # Redirect to user_articles route
        else:
            flash('User ID not found in session. Please log in again.', 'danger')
            return redirect(url_for('login'))


# Route for displaying user articles
@app.route('/user_articles')
def user_articles():
    if is_logged_in():
        # Fetch articles from the database for the logged-in user
        conn = sqlite3.connect('news_aggregator.db')
        c = conn.cursor()
        c.execute("SELECT * FROM articles WHERE user_id = ?", (session['user_id'],))
        user_articles = c.fetchall()
        conn.close()
        return render_template('user_articles.html', user_articles=user_articles)
    else:
        flash('You need to login first to view your articles.', 'danger')
        return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
