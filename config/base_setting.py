from datetime import timedelta
import os

AUTH_COOKIE_NAME = "dts_admin"

# session
SECRET_KEY = os.urandom(24)
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)