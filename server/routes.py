from server import app, db, jwt
from flask import request, abort
from werkzeug.security import generate_password_hash, check_password_hash
from server.models import User, Book
from server.redis import jwt_redis_blocklist
from server.utils.utils import ACCESS_EXPIRES
from sqlalchemy import exc
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt)


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]

    try:
        token_in_redis = jwt_redis_blocklist.get(jti)
    except exc.IntegrityError:
        abort(400, 'Token could not be reached')

    return token_in_redis is not None


@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = User.query.filter_by(id=get_jwt_identity()).first()

    if not current_user.admin:
        abort(401, "No permisson for user")

    users = User.query.all()

    if not users:
        abort(401, 'Users do not exist')

    output = [user.to_dict() for user in users]

    return {"users": output}


@app.route('/user/<id>', methods=['GET'])
@jwt_required()
def get_one_user(id):
    current_user = User.query.filter_by(id=get_jwt_identity()).first()

    if not current_user.admin:
        return abort(401, "No permisson for user")

    user = User.query.filter_by(id=id).first()

    if not user:
        abort(401, 'User does not exist')

    return {"user": user.to_dict()}


@app.route('/user', methods=['POST'])
@jwt_required()
def create_user():
    current_user = User.query.filter_by(id=get_jwt_identity()).first()

    if not current_user.admin:
        abort(401, "No permisson for user")

    data = request.get_json()
    users = User.query.all()

    if not users:
        abort(401, 'Users do not exist')

    for user in users:
        if data["username"] == user.username:
            abort(401, "Username is aready in use")

    hashed_password = generate_password_hash(
        data["password"], method=app.config["HASH_ALGORITHM"])

    new_user = User(
        username=data["username"],
        password=hashed_password,
        admin=False)

    try:
        db.session.add(new_user)
        db.session.commit()
    except exc.IntegrityError:
        abort(400, 'User already exists')
    except exc.SQLAlchemyError:
        abort(500, 'Internal server error')

    return {"message": "New user created!"}


@app.route('/user/<id>', methods=['PATCH'])
@jwt_required()
def promote_user(id):
    current_user = User.query.filter_by(id=get_jwt_identity()).first()

    if not current_user.admin:
        abort(401, "No permisson for user")

    user = User.query.filter_by(id=id).first()

    if not user:
        abort(401, 'User does not exist')

    user.admin = True

    try:
        db.session.commit()
    except exc.SQLAlchemyError:
        abort(500, 'Internal server error')

    return {"message": "The user has been prometed to admin"}


@app.route('/user/<id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    if not id:
        abort(400, 'User ID not provided')

    current_user = User.query.filter_by(id=get_jwt_identity()).first()

    if not current_user.admin:
        abort(401, "No permisson for user")

    user = User.query.filter_by(id=id).first()

    if not user:
        abort(401, 'User does not exist')

    try:
        db.session.delete(user)
        db.session.commit()
    except exc.SQLAlchemyError:
        abort(500, 'Internal server error')

    return {"message": "The user has been deleted!"}


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        abort(401, 'Invalid request')

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        abort(401, 'User does not exist')

    if check_password_hash(user.password, auth.password):
        token = create_access_token(identity=user.id)
        return {"token": token}

    return {"message": "Could not verify"}, 401


@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']

    try:
        jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
    except Exception:
        abort(404, 'Logout unsuccesful')

    return {"msg": "Token has been revoked"}, 200


@app.route('/book', methods=['GET'])
@jwt_required()
def get_author_books():
    current_user = User.query.filter_by(id=get_jwt_identity()).first()
    books = Book.query.filter_by(user_id=current_user.id).all()

    if not books:
        abort(401, 'Books do not exist')

    output = [book.to_dict() for book in books]

    return {"author_books": output}


@app.route('/book/<id>', methods=['GET'])
@jwt_required()
def get_one_book(id):
    if not id:
        abort(400, 'Book ID not provided')

    book = Book.query.filter_by(id=id).first()

    if not book:
        abort(401, 'Book does not exist')

    return {"book": book.to_dict()}


@app.route('/book/<id>', methods=['DELETE'])
@jwt_required()
def delete_author_book(id):
    if not id:
        abort(400, 'Book ID not provided')

    book = Book.query.filter_by(id=id).first()

    if not book:
        abort(401, 'Book does not exist')

    try:
        db.session.delete(book)
        db.session.commit()
    except exc.SQLAlchemyError:
        abort(500, 'Internal server error')

    return {"message": "The book deleted!"}


@app.route('/book/<id>', methods=['PUT'])
@jwt_required()
def edit_author_book(id):
    if not id:
        abort(400, 'Book ID not provided')

    data = request.get_json()
    book = Book.query.filter_by(id=id).first()

    if not book:
        abort(401, 'Book does not exist')

    if "title" in data:
        book.title = data["title"]
    if "complete" in data:
        book.complete = data["complete"]

    try:
        db.session.commit()
    except exc.SQLAlchemyError:
        abort(500, 'Internal server error')

    return {"book": book.to_dict()}


@app.route('/book', methods=['POST'])
@jwt_required()
def add_author_book():
    current_user = User.query.filter_by(id=get_jwt_identity()).first()
    data = request.get_json()

    book = Book(
        title=data["title"],
        complete=data["complete"],
        user_id=current_user.id)

    try:
        db.session.add(book)
        db.session.commit()
    except exc.SQLAlchemyError:
        abort(500, 'Internal server error')

    return {"message": "New book added!"}
