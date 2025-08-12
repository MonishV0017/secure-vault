import random
import string

def generate_captcha(): # Generates a 6-character alphanumeric CAPTCHA
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))