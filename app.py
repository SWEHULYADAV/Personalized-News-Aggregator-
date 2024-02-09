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
    c.execute('''CREATE TABLE IF NOT EXISTS preferences 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, category TEXT)''')
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
def save_user_to_database(username, hashed_password):  # Add hashed_password as an argument
    # Placeholder code to save user to the database
    # You need to replace this with your actual database logic
    conn = sqlite3.connect('news_aggregator.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

# Homepage route
@app.route('/')
def index():
    if is_logged_in():
        # Get top headlines using API key
        api_key = 'fbe4e4dc0f944629b23db0c5f03a210b'  # Replace with your API key
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
        flash('You have successfully signed up! Please log in.', 'success')  # Flash message for successful signup
        # Redirect user to login page after successful signup
        return redirect(url_for('login'))
    # If GET request, simply render the signup form
    return render_template('signup.html')  # Assuming you have a signup.html template

# Logout route
@app.route('/logout')
def logout():
    # Logout logic goes here
    pass

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
