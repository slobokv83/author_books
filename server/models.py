from server import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(64), unique=True)
    username = db.Column(db.String(64))
    password = db.Column(db.String(120))
    admin = db.Column(db.Boolean)
    book = db.relationship("Book", backref='author', lazy='dynamic')

# author_book = db.Table()

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.String(120), unique=True)
    title = db.Column(db.String(120))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))