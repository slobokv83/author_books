import os


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False