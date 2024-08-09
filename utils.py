import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app

def generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_otp_to_email(user_email, otp_code):
    """Send an OTP to the specified email address."""
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'tiketitamasha@gmail.com'  
    smtp_password = 'ynmy vlwl dmui labp '

    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp_code}"
    message = MIMEMultipart()
    message['From'] = smtp_username
    message['To'] = user_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls() 
            server.login(smtp_username, smtp_password)
            server.send_message(message)
        current_app.logger.info(f"OTP sent to {user_email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send OTP: {e}")
