from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize MySQL
mysql = MySQL(app)

# Decorator untuk memeriksa apakah user sudah login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator untuk memeriksa role admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_role' not in session or session['user_role'] != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = 'user'  # Default role for new registrations
        
        cur = mysql.connection.cursor()
        
        # Check if username exists
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        # Hash password and insert user
        password_hash = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                   (username, email, password_hash, role))
        mysql.connection.commit()
        cur.close()
        
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        
        if user and check_password_hash(user[3], password):  # user[3] is password_hash
            session['user_id'] = user[0]    # user[0] is id
            session['user_role'] = user[4]  # user[4] is role
            session['username'] = user[1]   # user[1] is username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()
    if session['user_role'] == 'admin':
        cur.execute("SELECT * FROM users")
    else:
        # Regular users can only see their own information
        cur.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    users = cur.fetchall()
    cur.close()
    return render_template('dashboard.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        cur = mysql.connection.cursor()
        password_hash = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                   (username, email, password_hash, role))
        mysql.connection.commit()
        cur.close()
        
        flash('User added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_user.html')

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if session['user_role'] != 'admin' and session['user_id'] != id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (id,))
    user = cur.fetchone()
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role'] if session['user_role'] == 'admin' else user[4]
        
        if request.form['password']:
            password_hash = generate_password_hash(request.form['password'])
            cur.execute("UPDATE users SET username = %s, email = %s, password_hash = %s, role = %s WHERE id = %s",
                       (username, email, password_hash, role, id))
        else:
            cur.execute("UPDATE users SET username = %s, email = %s, role = %s WHERE id = %s",
                       (username, email, role, id))
        
        mysql.connection.commit()
        cur.close()
        flash('User updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>')
@login_required
@admin_required
def delete_user(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
    
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        # Validasi input
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('add_user'))
            
        try:
            cur = mysql.connection.cursor()
            
            # Cek apakah username sudah ada
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                flash('Username already exists', 'error')
                return redirect(url_for('add_user'))
            
            # Cek apakah email sudah ada
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash('Email already exists', 'error')
                return redirect(url_for('add_user'))
            
            # Hash password dan simpan user
            password_hash = generate_password_hash(password)
            cur.execute("""
                INSERT INTO users (username, email, password_hash, role) 
                VALUES (%s, %s, %s, %s)
            """, (username, email, password_hash, role))
            
            mysql.connection.commit()
            cur.close()
            
            flash('User added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error adding user: {str(e)}', 'error')
            return redirect(url_for('add_user'))
    
    return render_template('add_user.html')