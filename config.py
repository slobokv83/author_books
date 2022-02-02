import os
from server.utils.utils import ACCESS_EXPIRES


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = ACCESS_EXPIRES
    HASH_ALGORITHM = os.environ.get('HASH_ALGORITHM')