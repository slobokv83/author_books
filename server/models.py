from sqlalchemy.dialects.postgresql import UUID
import uuid
from server import db


author_book = db.Table(
    'author_book',
    db.Column('user_id', UUID(as_uuid=True), db.ForeignKey('user.id'),
              primary_key=True),
    db.Column('book_id', UUID(as_uuid=True),
              db.ForeignKey('book.id'), primary_key=True)
)


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    username = db.Column(db.String(64))
    password = db.Column(db.String(120))
    admin = db.Column(db.Boolean)
    bk_id = db.relationship("Book", secondary=author_book,
                            back_populates='usr_id', lazy='dynamic')

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "password": self.password,
            "admin": self.admin,
            "bk_id": self.bk_id
        }


class Book(db.Model):
    __tablename__ = 'book'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    title = db.Column(db.String(120))
    complete = db.Column(db.Boolean)
    usr_id = db.relationship("User", secondary=author_book,
                            back_populates='bk_id', lazy='dynamic')

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "complete": self.complete,
        }
