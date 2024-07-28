# MFA Security for Global Bank Online Banking Platform

## Overview

In today's digital age, online banking has become an integral part of daily life for many individuals. With the convenience of accessing financial services from anywhere, comes the responsibility of ensuring the security and integrity of users' accounts and transactions. As cyber threats continue to evolve, it's imperative for financial institutions like Global Bank to implement robust security measures to safeguard against unauthorized access, data breaches, and fraudulent activities.

## Username & Password Authentication

The Username & Password Authentication Scheme is a widely adopted method for verifying the identity of users accessing online services. It involves users providing a unique username and a corresponding password to gain access to their accounts. This scheme serves as the first line of defense against unauthorized access, requiring users to prove their identity before accessing sensitive information or conducting transactions.

### Key Components

- **Secure Access Control**: Ensures that only authenticated users with valid credentials are granted access to specific pages or functionalities within the online banking platform.
- **Password Management**: Includes enforcing password complexity requirements, implementing password hashing and salting techniques, and enforcing periodic password changes.
- **User Authentication**: May involve multi-factor authentication (MFA) methods such as SMS codes, admin authorization, or one-time passwords (OTP) in addition to username and password credentials.

## Methodology

### Requirement Analysis

- Gather requirements from stakeholders, including Global Bank's management and end-users.
- Identify key functionalities and security requirements for the online banking platform.
- Define user roles and access control requirements.

### Design Phase

- Design the database schema using SQLite for storing user credentials, login attempts, and account status.
- Define the page-level security protocol, including username & password authentication, OTP verification, and account locking mechanisms.
- Create wireframes or mockups to visualize the user interface for registration, login, OTP verification, and account unlocking functionalities.

### Implementation

- Set up a Flask web application to serve as the backend for the online banking platform.
- Implement the User model class to represent user data in the database using SQLAlchemy.
- Develop routes and views for registration, login, OTP verification, account locking, and unlocking functionalities.
- Implement password hashing and salting techniques to securely store user passwords.
- Integrate email functionality to send OTPs, account lock notifications, and password reset messages using the SMTP protocol.

### Testing

- Perform unit testing to validate the functionality of individual components.
- Conduct integration testing to ensure seamless interaction between different modules and components.
- Perform security testing to identify vulnerabilities such as SQL injection, cross-site scripting (XSS), and session management flaws.

### Deployment

- Deploy the Flask application on a production server, ensuring proper configuration for security and performance.
- Set up SSL/TLS encryption to secure communication between clients and the server.
- Configure logging and monitoring mechanisms to track application usage, errors, and security events.

### Maintenance and Updates

- Regularly update the application to incorporate security patches, bug fixes, and new features.
- Monitor server performance and security logs to detect and mitigate any potential security threats or issues.
- Conduct periodic security audits and vulnerability assessments to ensure compliance with industry standards and regulations.
- Provide user training and support to address any queries or issues related to the online banking platform.

## Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/MandarKelkarOfficial/MFA.git
   cd online-banking-platform
   ```

2. **Create a Virtual Environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up the Database**:

   ```bash
   flask db init
   flask db migrate -m "Initial migration."
   flask db upgrade
   ```

5. **Run the Application**:
   ```bash
   flask run
   ```

## Screenshots

![Registration Page](/static/img/register.png)
_Figure 1: User Registration Page_

![Login Page](/static/img/validation.png)
_Figure 2: Validations_

![Login Page](/static/img/admin.png)
_Figure 3: Admin Page_

![OTP Verification](/static/img/otp.png)
_Figure 4: OTP Verification Page_

![Account Lock Notification](/static/img/account_locked.png)
_Figure 5: Account Lock Notification_

By following this methodology, Global Bank can effectively develop and deploy a secure online banking platform that meets the needs of its users while mitigating security risks and ensuring compliance with regulatory requirements.

---
