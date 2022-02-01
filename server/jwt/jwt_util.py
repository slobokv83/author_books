import logging, jwt
from flask import request, jsonify
from functools import wraps
from server import app
from server.models import User

def token_required(fun):
    @wraps(fun)# proveri zasto se stavlja wraps. zato sto moze da ne vrati objekat
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers.get("x-access-token") #request.environ['HTTP_X_ACCESS_TOKEN']
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                algorithms=["HS256"])
            current_user = User.query.filter_by(
                public_id=data["public_id"]).first()
        except Exception as e:
            # logging.info(e)
            return jsonify({"message": "The token is invalid!"})
        return fun(current_user, *args, **kwargs)
    return decorated