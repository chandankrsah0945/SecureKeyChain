from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import logging
import os

# Initialize logging
# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.WARNING)


# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Configure Database (PostgreSQL or SQLite)
USE_POSTGRES = True  # Set to False to use SQLite
if USE_POSTGRES:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root1234@localhost/passdmgr'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db)

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'admin' or 'user'

# Ensure the SECRET_KEY is 32 bytes long (256 bits)
SECRET_KEY = b'this_is_a_fixed_32_byte_key_1234'  # Replace with a fixed key of 32 bytes

# Debug the key
logging.debug(f"SECRET_KEY: {SECRET_KEY}, Length: {len(SECRET_KEY)}")

# Verify the key length
if len(SECRET_KEY) not in [16, 24, 32]:
    raise ValueError("SECRET_KEY must be 16, 24, or 32 bytes long")

def encrypt_password(password):
    logging.debug(f"Original password: {password}")
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded_data = pad(password.encode(), AES.block_size)
    logging.debug(f"Padded data: {padded_data}")
    encrypted = cipher.encrypt(padded_data)
    logging.debug(f"Encrypted data: {encrypted}")
    return base64.b64encode(encrypted).decode()  # Return Base64-encoded string

def decrypt_password(encrypted_password):
    logging.debug(f"Encrypted password: {encrypted_password}")

    if not encrypted_password:
        raise ValueError("Encrypted password is empty or invalid")

    try:
        cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_password))
        logging.debug(f"Decrypted data (before unpadding): {decrypted}")
        # Remove padding using unpad
        unpadded_data = unpad(decrypted, AES.block_size)
        logging.debug(f"Decrypted data (after unpadding): {unpadded_data}")
        return unpadded_data.decode()  # Return the clean password
    except (ValueError, Exception) as e:
        logging.error(f"Failed to decrypt password: {e}")
        raise ValueError(f"Failed to decrypt password: {e}")

# Update the Credential model
class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    # password = db.Column(db.String(128), nullable=False)  # Hashed password
    encrypted_password = db.Column(db.Text, nullable=False)  # Encrypted password
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('credentials', lazy=True))

# Repopulate encrypted_password for existing credentials
with app.app_context():
    credentials = Credential.query.all()
    for credential in credentials:
        credential.encrypted_password = encrypt_password(credential.encrypted_password)
        db.session.commit()

# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        role = 'user'  # Default role is 'user'

        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'warning')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role)

        db.session.add(new_user)
        db.session.commit()

        flash(f'User {username} created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# admin_login
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Look for a user with admin role and matching email
        user = User.query.filter_by(email=email, role='admin').first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')

    return render_template('admin_login.html')

# admin_dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))

    users = User.query.all()
    return render_template('admin_dashboard.html', username=current_user.username, users=users)


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            if user.role == 'admin':
                flash('Admins must log in through the Admin Login page.', 'warning')
                return redirect(url_for('login'))

            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))

        flash('Invalid email or password', 'danger')

    return render_template('login.html')


# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.all()
        return render_template('admin_dashboard.html', username=current_user.username, users=users)
    else:
        # Fetch credentials for the logged-in user
        credentials = Credential.query.filter_by(user_id=current_user.id).all()
        return render_template('user_dashboard.html', username=current_user.username, credentials=credentials)

# Delete User (Admin Only)
@app.route('/delete/<int:id>')
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))

    user_to_delete = db.session.get(User, id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully.', 'success')

    return redirect(url_for('dashboard'))

# Update User (Admin Only)
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user(id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))

    user = db.session.get(User, id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_username = request.form.get('username').strip()
        new_email = request.form.get('email').strip()
        new_password = request.form.get('password')
        new_role = request.form.get('role', 'user').strip().lower()

        if not new_username or not new_email:
            flash("All fields are required.", "danger")
            return redirect(url_for('update_user', id=id))

        if User.query.filter(User.email == new_email, User.id != id).first():
            flash('Email already in use by another account!', 'warning')
            return redirect(url_for('update_user', id=id))

        if new_password:
            if bcrypt.check_password_hash(user.password, new_password):
                flash("New password cannot be the same as the old password.", "danger")
                return redirect(url_for('update_user', id=id))
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password

        user.username = new_username
        user.email = new_email
        user.role = new_role

        db.session.commit()
        flash("User information updated successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template('update.html', user=user)

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Get Password Route (Admin Only)
@app.route('/get_password/<int:user_id>')
@login_required
def get_password(user_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Access denied!"}), 403

    user = db.session.get(User, user_id)
    if user:
        return jsonify({"password": user.password})  # Return hashed password
    else:
        return jsonify({"error": "User not found!"}), 404

# Reset Password Route (Admin Only)
@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))

    user = db.session.get(User, user_id)
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if new_password:
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash('Password reset successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('reset_password.html', user=user)

# Add Credential Route
key = "this_is_a_fixed_32_byte_key_1234"
key_bytes = key.encode()  # convert str to bytes
encoded_key = base64.urlsafe_b64encode(key_bytes)  # now safe
fernet = Fernet(encoded_key)

# Add Credential Route
@app.route('/add_credential', methods=['GET', 'POST'])
@login_required
def add_credential():
    if request.method == 'POST':
        site_name = request.form.get('site_name')
        username = request.form.get('username')
        password = request.form.get('password')  # Get plain password from form

        if not site_name or not username or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('add_credential'))

        # Encrypt the password for secure storage (permanent)
        encrypted_password = fernet.encrypt(password.encode()).decode('utf-8')

        # Create new credential record
        new_credential = Credential(
            site_name=site_name,
            username=username,
            encrypted_password=encrypted_password,
            user_id=current_user.id
        )

        db.session.add(new_credential)
        db.session.commit()

        flash('Credential added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_credential.html')

# Get Original Password Route
@app.route('/get_original_password/<int:credential_id>')
@login_required
def get_original_password(credential_id):
    credential = Credential.query.get_or_404(credential_id)

    if credential.user_id != current_user.id:
        return jsonify({"error": "Access denied!"}), 403

    try:
        original_password = fernet.decrypt(credential.encrypted_password.encode()).decode()
        return jsonify({"password": original_password})
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return jsonify({"error": "Failed to decrypt password."}), 400


# View Credentials Route
@app.route('/view_credentials')
@login_required
def view_credentials():
    credentials = Credential.query.filter_by(user_id=current_user.id).all()
    return render_template('view_credentials.html', credentials=credentials)

# Update Credential Route
@app.route('/update_credential/<int:credential_id>', methods=['GET', 'POST'])
@login_required
def update_credential(credential_id):
    credential = Credential.query.get_or_404(credential_id)

    if credential.user_id != current_user.id:
        flash('Access denied!', 'danger')
        return redirect(url_for('view_credentials'))

    if request.method == 'POST':
        site_name = request.form.get('site_name')
        username = request.form.get('username')
        password = request.form.get('password')

        if not site_name or not username or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('update_credential', credential_id=credential_id))

        # Encrypt the new password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        credential.site_name = site_name
        credential.username = username
        credential.encrypted_password = hashed_password

        db.session.commit()
        flash('Credential updated successfully!', 'success')
        return redirect(url_for('view_credentials'))

    return render_template('update_credential.html', credential=credential)

# Delete Credential Route
@app.route('/delete_credential/<int:credential_id>')
@login_required
def delete_credential(credential_id):
    credential = Credential.query.get_or_404(credential_id)

    if credential.user_id != current_user.id:
        flash('Access denied!', 'danger')
        return redirect(url_for('view_credentials'))

    db.session.delete(credential)
    db.session.commit()
    flash('Credential deleted successfully!', 'success')
    return redirect(url_for('view_credentials'))

# Get Credential Password Route
@app.route('/get_credential_password/<int:credential_id>')
@login_required
def get_credential_password(credential_id):
    credential = Credential.query.get_or_404(credential_id)

    if credential.user_id != current_user.id:
        return jsonify({"error": "Access denied!"}), 403

    return jsonify({"password": credential.encrypted_password})  # Return hashed password

# Run the App
if __name__ == '__main__':
    if not os.path.exists('instance'):
        os.makedirs('instance')
    with app.app_context():
        db.create_all()
    app.run(debug=True)