from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import *
import pyotp
import qrcode
import io
import base64
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'secret123'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.LargeBinary)
    otp_secret = db.Column(db.String(100))
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)

from datetime import datetime
import pytz

def ist_time():
    return datetime.now(pytz.timezone('Asia/Kolkata'))

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    time = db.Column(db.DateTime, default=ist_time)  # ✅ CORRECT
class ActivityLogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    activity = db.Column(db.String(200))
    time = db.Column(db.DateTime, default=ist_time)
class SecurityAlerts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    alert = db.Column(db.String(200))
    time = db.Column(db.DateTime, default=ist_time)
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return redirect(url_for('login'))
import re

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        # EMAIL VALIDATION
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

        if not re.match(email_pattern, username):

            flash("Enter a valid email address")
            return redirect(url_for('register'))

        # PASSWORD VALIDATION
        password_pattern = r'^(?=.*[!@#$%^&*(),.?\":{}|<>]).{8,}$'

        if not re.match(password_pattern, password):

            flash("Password must contain 8 characters and one special character")
            return redirect(url_for('register'))

        # CHECK EXISTING USER
        if User.query.filter_by(username=username).first():

            flash("User already exists")
            return redirect(url_for('register'))

        # HASH PASSWORD
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # GENERATE OTP SECRET
        otp_secret = pyotp.random_base32()

        # SAVE USER
        user = User(
            username=username,
            password=hashed,
            otp_secret=otp_secret
        )

        db.session.add(user)
        db.session.commit()

        # ACTIVITY LOG
        log = ActivityLogs(

            username=username,

            activity="User Registered"
        )

        db.session.add(log)
        db.session.commit()

        flash("Registered successfully! Please login.")

        return redirect(url_for('login'))

    return render_template("register.html")
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user:

            # Check if account is locked
            if user.is_locked:
                flash("Account Locked Due To Multiple Failed OTP Attempts")
                return redirect(url_for('login'))

            # Check password
            if bcrypt.checkpw(password.encode(), user.password):

                session['temp_user'] = username
                return redirect(url_for('otp'))

        flash("Invalid credentials")
        return redirect(url_for('login'))

    return render_template("login.html")
@app.route('/otp')
def otp():
    username = session.get('temp_user')
    if not username:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    totp = pyotp.TOTP(user.otp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SecureApp")

    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    return render_template("otp.html", qr_code=qr_code)

@app.route('/verify', methods=['POST'])
def verify():
    username = session.get('temp_user')
    user = User.query.filter_by(username=username).first()
    if user.is_locked:
          flash("Account Locked Due To Multiple Failed OTP Attempts")
          return redirect(url_for('login'))


    otp = request.form.get('otp')
    totp = pyotp.TOTP(user.otp_secret)

    # SUCCESSFUL OTP
    if totp.verify(otp):

        session['user'] = username
        session['authenticated'] = True
        session.pop('temp_user', None)

        # Login history
        db.session.add(LoginHistory(username=username))

        # Activity log
        activity = ActivityLogs(
            username=username,
            activity="Login Successful with OTP"
        )

        db.session.add(activity)
        user.failed_attempts = 0
        db.session.commit()

        return redirect(url_for('dashboard'))

    # FAILED OTP

    # Activity log
    failed_log = ActivityLogs(
        username=username,
        activity="Failed OTP Attempt"
    )

    db.session.add(failed_log)

    # Security alert
    security = SecurityAlerts(
        username=username,
        alert="Suspicious Failed OTP Attempt"
    )

    db.session.add(security)
    user.failed_attempts += 1

    if user.failed_attempts >= 3:

    # Do not lock admin
     if username != "admin@gmail.com":
        user.is_locked = True

    db.session.commit()

    flash("Invalid OTP")
    return redirect(url_for('otp'))

from collections import Counter

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login'))

    logs = LoginHistory.query.filter_by(username=session['user']).all()
    security_alerts = SecurityAlerts.query.filter_by(
    username=session['user']
     ).all()
    # Count logins per day
    dates = [log.time.strftime('%Y-%m-%d') for log in logs]
    count_data = Counter(dates)

    labels = list(count_data.keys())
    values = list(count_data.values())

    return render_template(
        "dashboard.html",
        logs=logs,
        labels=labels,
        values=values,
        security_alerts=security_alerts
    )

@app.route('/admin')
def admin():
    if not session.get('authenticated'):
        return redirect(url_for('login'))

    if session.get('user') != "admin@gmail.com":
        return render_template("access_denied.html")

    users = User.query.all()
    logs = LoginHistory.query.all()
    activity_logs = ActivityLogs.query.all()
    security_alerts = SecurityAlerts.query.all()
    active_users = User.query.filter_by(is_locked=False).count()
    locked_users = User.query.filter_by(is_locked=True).count()

    return render_template(
        "admin.html",
        users=users,
        logs=logs,
        activity_logs=activity_logs,
        security_alerts=security_alerts,
        active_users=active_users,
        locked_users=locked_users
    )
@app.route('/delete_user/<int:id>')
def delete_user(id):

    user = User.query.get(id)

    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('admin'))
@app.route('/unlock_user/<int:id>')
def unlock_user(id):

    user = User.query.get(id)

    if user:

        user.failed_attempts = 0
        user.is_locked = False

        db.session.commit()

    return redirect(url_for('admin'))
@app.route('/logout')
def logout():

    if session.get('user'):
        log = ActivityLogs(
            username=session.get('user'),
            activity="User Logged Out"
        )

        db.session.add(log)
        db.session.commit()

    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)