from dotenv import load_dotenv
import os
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
EMAIL = os.getenv("EMAIL")
EMAIL_PASSWORD = os.getenv("EMIL_PASSWORD")

# FLASK_URL = 'http://127.0.0.1:5000'


FLASK_URL = 'http://35.154.190.245:5000'


