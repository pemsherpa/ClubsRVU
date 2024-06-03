

from flask import Flask, render_template, request, redirect, url_for, flash, g, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'database.db'
rep_club = ['president']  # Add president to rep_club by default

def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    print("Initializing the database...")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            event_name TEXT NOT NULL,
            club TEXT NOT NULL,
            description TEXT NOT NULL
        );


        CREATE TABLE IF NOT EXISTS clubs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            club_name TEXT NOT NULL,
            representative TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()
    print("Database initialized.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'president' and password == 'abcd':
            session['username'] = username
            if username not in rep_club:
                rep_club.append(username)
            flash('Login successful!', 'success')
            return redirect(url_for('home_pres'))
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already exists', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            print(f"User {username} added to the database with hashed password {hashed_password}.")
            conn.close()
            flash('Sign up successful! Redirecting to home page.', 'success')
            return redirect(url_for('home'))
        conn.close()
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    events = conn.execute('SELECT * FROM events').fetchall()
    clubs = conn.execute('SELECT * FROM clubs').fetchall()
    conn.close()
    return render_template('home.html', events=events, clubs=clubs, current_user=session['username'])

@app.route('/home_pres', methods=['GET', 'POST'])
def home_pres():
    if 'username' not in session or session['username'] != 'president':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        club_name = request.form['club_name']
        representative = request.form['representative']
        conn = get_db_connection()
        conn.execute('INSERT INTO clubs (club_name, representative) VALUES (?, ?)', (club_name, representative))
        conn.commit()
        rep_club.append(representative)
        flash('Club created successfully!', 'success')
    conn = get_db_connection()
    events = conn.execute('SELECT * FROM events').fetchall()
    clubs = conn.execute('SELECT * FROM clubs').fetchall()
    conn.close()  # Close connection after fetching clubs
    return render_template('home_pres.html', events=events, clubs=clubs, current_user=session['username'])



@app.route('/calendar')
def calendar():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    username = session['username']
    conn = get_db_connection()
    clubs = conn.execute('SELECT * FROM clubs').fetchall()
    # Retrieve the list of club representatives from the database
    rep_club_db = conn.execute('SELECT representative FROM clubs').fetchall()
    rep_club_db = [row['representative'] for row in rep_club_db]

    # Ensure rep_club includes both static and dynamic representatives
    rep_club.extend(rep_club_db)

    # Check if the user is a president or a club representative
    is_president = username == 'president'
    is_representative = username in rep_club

    if is_president or is_representative:
        events = conn.execute('SELECT * FROM events').fetchall()
        clubs = conn.execute('SELECT * FROM clubs').fetchall()
        conn.close()

        # Render the appropriate template based on the user's role
        if is_president:
            home_url = url_for('home_pres')
        else:
            home_url = url_for('home')

        return render_template('calendar.html', events=events, clubs=clubs, home_url=home_url)
    else:
        conn.close()
        # Render the calendar_user.html template if the user is not a president or a club representative
        return render_template('calendar_user.html', current_user=username,clubs=clubs )


@app.route('/add_event', methods=['POST'])
def add_event():
    if 'username' not in session:
        flash('Please log in to add an event.', 'danger')
        return redirect(url_for('login'))
    date = request.form['date']
    time = request.form['time']
    event_name = request.form['event_name']
    club = request.form['club']
    description = request.form['description']
    conn = get_db_connection()
    conn.execute('INSERT INTO events (date, time, event_name, club, description) VALUES (?, ?, ?, ?, ?)',
                 (date, time, event_name, club, description))
    conn.commit()
    conn.close()
    flash('Event added successfully!', 'success')
    return redirect(url_for('calendar'))



@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
