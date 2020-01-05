import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config():
    DEBUG = False
    ENV = 'production'
    DATABASE_URI = 'sqlite:///'+os.path.join(BASE_DIR, 'prod.db')
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'secret-key'

class DevelopmentConfig(Config):       
    DEBUG = True   
    ENV = 'developement'
    DATABASE_URI = 'sqlite:///'+os.path.join(BASE_DIR, 'dev.db')                  
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'secret-key'