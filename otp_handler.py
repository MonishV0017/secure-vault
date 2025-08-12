import os
import random
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

def generate_otp(length: int = 6) -> str: # Generates a random numeric OTP string
    return str(random.randint(0, 10**length - 1)).zfill(length)

def send_otp(email: str, otp: str) -> None: # Sends a standard verification OTP email
    msg = EmailMessage()
    msg.set_content(f'Your Secure Vault verification code is: {otp}')
    msg['Subject'] = 'Secure Vault Verification Code'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

def send_factory_reset_otp(email: str, otp: str) -> None: # Sends a high-warning factory reset OTP email
    msg = EmailMessage()
    msg.set_content(f'Your verification code for a FACTORY RESET of your Secure Vault is: {otp}\n\nIf you did not request this, someone is trying to erase all application data. IGNORE THIS EMAIL.')
    msg['Subject'] = 'CRITICAL ALERT: Secure Vault Factory Reset Requested'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)