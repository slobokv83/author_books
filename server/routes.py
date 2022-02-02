import uuid
from server import app, db, jwt
from flask import request, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from server.models import User, Book
from server.redis import jwt_redis_blocklist
from server.utils.utils import ACCESS_EXPIRES
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt)


# Callback function to check if a JWT exists in the redis blocklist
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None

@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():
    current_id = get_jwt_identity()
    current_user = User.query.filter_by(public_id=current_id).first()

    if not current_user.admin:
        return {"message": "No permisson for the operation"}
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data["public_id"] = user.public_id
        user_data["username"] = user.username
        user_data["password"] = user.password
        user_data["admin"] = user.admin
        output.append(user_data)

    return {"users": output}

@app.route('/user/<public_id>', methods=['GET'])
@jwt_required()
def get_one_user(public_id):
    current_id = get_jwt_identity()
    current_user = User.query.filter_by(public_id=current_id).first()

    if not current_user.admin:
        return {"message": "No permisson for the operation"}
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return {"message": "No user found!"}
    user_data = {}
    user_data["public_id"] = user.public_id
    user_data["username"] = user.username
    user_data["password"] = user.password
    user_data["admin"] = user.admin

    return {"user": user_data}

@app.route('/user', methods=['POST'])
@jwt_required()
def create_user():
    current_id = get_jwt_identity()
    current_user = User.query.filter_by(public_id=current_id).first()

    if not current_user.admin:
        return {"message": "No permisson for the operation"}
    data = request.get_json()
    users = User.query.all()
    for user in users:
        if data["username"] == user.username:
            return {"message": "Username is aready in use"}
    hashed_password = generate_password_hash(
        data["password"], method=app.config["HASH_ALGORITHM"])
    new_user = User(
        public_id=str(uuid.uuid4()),
        username=data["username"],
        password=hashed_password,
        admin=False)
    db.session.add(new_user)
    db.session.commit()
    return {"message": "New user created!"}

@app.route('/user/<public_id>', methods=['PATCH'])# zasto moze i PUT?
@jwt_required()
def promote_user(public_id):
    current_id = get_jwt_identity()
    current_user = User.query.filter_by(public_id=current_id).first()

    if not current_user.admin:
        return {"message": "No permisson for the operation"}
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return {"message": "No user found!"}
    user.admin = True
    db.session.commit()
    return {"message": "The user has been prometed to admin"}

@app.route('/user/<public_id>', methods=['DELETE'])
@jwt_required()
def delete_user(public_id):
    current_id = get_jwt_identity()
    current_user = User.query.filter_by(public_id=current_id).first()
    
    if not current_user.admin:
        return {"message": "No permisson for the operation"}
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return {"message": "No user found!"}
    db.session.delete(user)
    db.session.commit()
    return {"message": "The user has been deleted!"}

@app.route('/login', methods=['POST'])# ako ne navedem metod, onda je GET?
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = create_access_token(identity=user.public_id)

        return {"token": token}

    return make_response('Could not verify', 401,
        {'WWW-Authenticate': 'Basic realm="Login required!"'})

@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
    create_access_token(identity="")
    return {"msg": "Access token revoked"}, 200


@app.route('/refresh_token', methods=['POST'])
@jwt_required()
def refresh():

    current_id = get_jwt_identity()
    ret = {
        'token': create_access_token(identity=current_id, expires_delta=None)
    }
    return ret, 200


@app.route('/book', methods=['GET'])
@jwt_required()
def get_author_books():
    current_id = get_jwt_identity()
    current_user = User.query.filter_by(public_id=current_id).first()

    books = Book.query.filter_by(user_id=current_user.public_id).all()
    output = []
    for book in books:
        book_data = {}
        book_data["book_id"] = book.book_id
        book_data["title"] = book.title
        book_data["complete"] = book.complete
        book_data["user_id"] = book.user_id
        output.append(book_data)
    return {"author_books": output}

@app.route('/book/<book_id>', methods=['GET'])
@jwt_required()
def get_one_book(book_id):
    book = Book.query.filter_by(book_id=book_id).first()
    if not book:
        return {"message": "No book found!"}
    book_data = {}
    book_data["book_id"] = book.book_id
    book_data["title"] = book.title
    book_data["complete"] = book.complete
    book_data["user_id"] = book.user_id
    return {"book": book_data}


@app.route('/book/<book_id>', methods=['DELETE'])
@jwt_required()
def delete_author_book(book_id):
    book = Book.query.filter_by(book_id=book_id).first()
    db.session.delete(book)
    db.session.commit()
    return {"message": "The book deleted!"}

@app.route('/book/<book_id>', methods=['PUT'])# moze i PATCH
@jwt_required()
def edit_author_book(book_id):
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
    return {"book": book_data}


@app.route('/book', methods=['POST'])
@jwt_required()
def add_author_book():
    current_id = get_jwt_identity()
    current_user = User.query.filter_by(public_id=current_id).first()

    data = request.get_json()
    book = Book(
        book_id=str(uuid.uuid4()),
        title = data["title"],
        complete = data["complete"],
        user_id = current_user.public_id
        )
    db.session.add(book)
    db.session.commit()
    return {"message": "New book added!"}
