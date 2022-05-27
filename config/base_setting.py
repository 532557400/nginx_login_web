from datetime import timedelta
import os

# session
SECRET_KEY = os.urandom(24)
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)