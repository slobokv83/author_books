from sqlalchemy.dialects.postgresql import UUID
import uuid
from server import db

class User(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    username = db.Column(db.String(64))
    password = db.Column(db.String(120))
    admin = db.Column(db.Boolean)
    book = db.relationship("Book", backref='author', lazy='dynamic')

# author_book = db.Table()

class Book(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    title = db.Column(db.String(120))
    complete = db.Column(db.Boolean)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'),
                        nullable=False)