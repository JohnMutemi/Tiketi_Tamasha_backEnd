import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', '51645sk0sgyuiw2rfgh5565g5d154g5')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', '276ww8hua5fd45d5g5d154gnshiwapwg')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)

    JSON_COMPACT = False

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True
    # SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


DEBUG=False