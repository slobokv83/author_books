import uuid, jwt
from server import app, db
from server.jwt.jwt_util import token_required
from flask import jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from server.models import User, Book

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({"message": "No permisson for the operation"})
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data["public_id"] = user.public_id
        user_data["username"] = user.username
        user_data["password"] = user.password
        user_data["admin"] = user.admin
        output.append(user_data)

    return jsonify({"users": output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "No permisson for the operation"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"})
    user_data = {}
    user_data["public_id"] = user.public_id
    user_data["username"] = user.username
    user_data["password"] = user.password
    user_data["admin"] = user.admin

    return jsonify({"user": user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message": "No permisson for the operation"})
    data = request.get_json()
    users = User.query.all()
    for user in users:
        if data["username"] == user.username:
            return jsonify({"message": "Username is aready in use"})
    hashed_password = generate_password_hash(data["password"], method="sha256")
    new_user = User(
        public_id=str(uuid.uuid4()),
        username=data["username"],
        password=hashed_password,
        admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "New user created!"})

@app.route('/user/<public_id>', methods=['PATCH'])# zasto moze i PUT?
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "No permisson for the operation"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"})
    user.admin = True
    db.session.commit()
    return jsonify({"message": "The user has been prometed to admin"})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "No permisson for the operation"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "The user has been deleted!"})

@app.route('/login')# ako ne navedem metod, onda je GET?
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm="Login required!"'})# zasto WWW-Authenticate - neka standardna forma?

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=180)
            }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({"token": token})# zasto nije binaran? nema .decode()

    return make_response('Could not verify', 401,
        {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/book', methods=['GET'])
@token_required
def get_author_books(current_user):
    books = Book.query.filter_by(user_id=current_user.public_id).all()
    output = []
    for book in books:
        book_data = {}
        book_data["book_id"] = book.book_id
        book_data["title"] = book.title
        book_data["complete"] = book.complete
        book_data["user_id"] = book.user_id
        output.append(book_data)
    return jsonify({"author_books": output})

@app.route('/book/<book_id>', methods=['GET'])
@token_required
def get_one_book(current_user, book_id):
    book = Book.query.filter_by(book_id=book_id).first()
    if not book:
        return jsonify({"message": "No book found!"})
    book_data = {}
    book_data["book_id"] = book.book_id
    book_data["title"] = book.title
    book_data["complete"] = book.complete
    book_data["user_id"] = book.user_id
    return jsonify({"book": book_data})


@app.route('/book/<book_id>', methods=['DELETE'])
@token_required
def delete_author_book(current_user, book_id):
    book = Book.query.filter_by(book_id=book_id).first()
    db.session.delete(book)
    db.session.commit()
    return jsonify({"message": "The book deleted!"})

@app.route('/book/<book_id>', methods=['PUT'])# moze i PATCH
@token_required
def edit_author_book(current_user, book_id):
    data = request.get_json()
    book = Book.query.filter_by(book_id=book_id).first()
    if "title" in data:
        book.title = data["title"]
    if "complete" in data:
        book.complete = data["complete"]
    db.session.commit()
    book_data = {}
    book_data["book_id"] = book.book_id
    book_data["complete"] = book.complete
    book_data["title"] = book.title
    book_data["user_id"] = book.user_id
    return jsonify({"book": book_data})


@app.route('/book', methods=['POST'])
@token_required
def add_author_book(current_user):
    data = request.get_json()
    book = Book(
        book_id=str(uuid.uuid4()),
        title = data["title"],
        complete = data["complete"],
        user_id = current_user.public_id
        )
    db.session.add(book)
    db.session.commit()
    return jsonify({"message": "New book added!"})