import os
import random
import smtplib
from email.message import EmailMessage


# Replace these with your actual admin email and Google App Password
EMAIL_ADDRESS = "your-email@gmail.com"
EMAIL_PASSWORD = "your-16-character-google-app-password"

# Generates a random numeric OTP string
def generate_otp(length: int = 6) -> str:
    return str(random.randint(0, 10**length - 1)).zfill(length)

# Sends a standard verification OTP email
def send_otp(email: str, otp: str) -> None:
    msg = EmailMessage()
    msg.set_content(f'Your Secure Vault verification code is: {otp}')
    msg['Subject'] = 'Secure Vault Verification Code'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# Sends a specific, high-warning OTP for factory reset
def send_factory_reset_otp(email: str, otp: str) -> None:
    msg = EmailMessage()
    msg.set_content(f'Your verification code for a FACTORY RESET of your Secure Vault is: {otp}\n\nIf you did not request this, someone is trying to erase all application data. IGNORE THIS EMAIL.')
    msg['Subject'] = 'CRITICAL ALERT: Secure Vault Factory Reset Requested'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)