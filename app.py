from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import random
import smtplib
import string
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key=secret_key = os.urandom(24)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    login_attempts = db.Column(db.Integer, default=0) 
    flag = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


def generate_otp():
    return str(random.randint(10000, 99999))


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def send_otp_to_email(receiver_email, otp):
    # Sender's email and password
    sender_email = "sdbcontactme@gmail.com"
    sender_password = "fywacjgevdugsgtz"

    # Create the message with the OTP
    message_body = f"Your OTP is: {otp}"
    subject = "OTP Verification"

    # Create an email message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(message_body, "plain"))

    # Set up the SMTP server and send the email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        print(f"OTP sent to {receiver_email}")
    except Exception as e:
        print(f"Failed to send OTP: {e}")


def send_email_on_failed_login(receiver_email):
    # Sender's email and password
    sender_email = "sdbcontactme@gmail.com"
    sender_password = "fywacjgevdugsgtz"

    # Create the message for failed login attempts
    message_body = f"Your account has been locked due to 3 consecutive failed login attempts. Please reset your password."
    subject = "Account Locked"

    # Create an email message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(message_body, "plain"))

    # Set up the SMTP server and send the email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        print(f"Email sent to {receiver_email} for failed login attempts.")
    except Exception as e:
        print(f"Failed to send email for failed login attempts: {e}")
        
        
def send_reset_password_email(receiver_email):
    # Sender's email and password
    sender_email = "sdbcontactme@gmail.com"
    sender_password = "fywacjgevdugsgtz"

    # Generate random alphanumeric string
    random_string = generate_random_string(10)

    # Create the message for reset password
    message_body = f"Your reset password code is: {random_string}"
    subject = "Reset Password"

    # Create an email message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(message_body, "plain"))

    # Set up the SMTP server and send the email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        print(f"Email sent to {receiver_email} for password reset.")
        return random_string  # Return the randomly generated string for verification
    except Exception as e:
        print(f"Failed to send email for password reset: {e}")
        return None


@app.route('/')
def index():
    return render_template('index.html')



@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'message': 'Username already exists!'}), 409
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return jsonify({'message': 'Email already exists!'}), 409

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/register', methods=['GET'])
def register_form():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user:
            if user.flag:  # Check if the flag is True
                if user.login_attempts >= 3:
                    send_email_on_failed_login(user.email)
                    return render_template('locked.html')
                
                if check_password_hash(user.password_hash, password):
                    user.login_attempts = 0  # Reset login attempts on successful login
                    db.session.commit()
                    global otp
                    otp = generate_otp()
                    send_otp_to_email(user.email, otp)
                    return render_template('otp1.html')
                else:
                    user.login_attempts += 1  # Increment login attempts on failed login
                    db.session.commit()
                    msg = jsonify({'message': 'Invalid username or password.'})
                    return render_template('login.html', error_message=msg) 
            else:
                # Display message indicating approval pending by admin
                error_message = 'Approval pending by admin. Please wait for approval.'
                return render_template('login.html', error_message=error_message)
        else:
            print("Approval pending by admin")
            error_message = 'User not found. Please check your username.'
            return render_template('login.html', error_message=error_message), 404
    return render_template('login.html')


@app.route('/otp', methods=['POST'])
def otp():
    if request.method == 'POST':
        user_otp = request.form['otp']  # Get the OTP entered by the user

        if user_otp == otp:  # Compare the user's OTP with the generated OTP
            print("true")  # Print "true" if the OTPs match
            return render_template('dashboard.html')
        else:
            print("false")  # Print "false" if the OTPs do not match

    return render_template('otp1.html')


# Route to render the unlock account form
@app.route('/unlock_account', methods=['GET'])
def unlock_account_form():
    return render_template('unlock.html')

# Route to handle unlocking the account
@app.route('/unlock_account', methods=['POST'])
def unlock_account():
    unlock_string = request.form['unlock']

    # Check if the unlock string matches the randomly generated string
    if unlock_string == session.get('unlock_string'):
        # Reset the login_attempts column to zero for the user
        user = User.query.filter_by(username=session.get('unlock_username')).first()
        if user:
            user.login_attempts = 0
            db.session.commit()
            return redirect(url_for('login'))  # Redirect to the index page
    else:
        return jsonify({'error': 'Invalid unlock string'}), 400  # Return an error if the strings do not match
    return render_template('unlock.html')

# Route to send the unlock message and generate the random string
@app.route('/send_unlock_msg', methods=['GET','POST'])
def send_unlock_msg():
    username = request.form['username']
    user = User.query.filter_by(username=username).first()

    if user:
        unlock_string = send_reset_password_email(user.email)
        if unlock_string:
            session['unlock_string'] = unlock_string
            session['unlock_username'] = username
            return redirect(url_for('unlock_account'))  # Redirect to the unlock account page
        else:
            return jsonify({'error': 'Failed to send unlock message'}), 500
    else:
        return jsonify({'error': 'User not found'}), 404
    return render_template('locked.html')


@app.route('/admin_mk',methods=['GET','POST'])
def display_users():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/set_flag/<int:user_id>', methods=['POST'])
def set_flag(user_id):
    user = User.query.get(user_id)
    if user:
        user.flag = True
        db.session.commit()
        return redirect(url_for('display_users'))
    else:
        return "User not found", 404
    
@app.route('/attack',methods=['GET','POST'])
def attack():
    # users = User.query.all()
    return render_template("attack.html")
    


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)
