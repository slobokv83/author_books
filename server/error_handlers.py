from server import app, db


def get_error_response(error, code):
    return {
        'message': str(error.description),
        'status': code
    }, code


@app.errorhandler(400)
def user_input_error(error):
    db.session.rollback()
    return get_error_response(error, 400)


@app.errorhandler(401)
def unauthorized_error(error):
    return get_error_response(error, 401)


@app.errorhandler(404)
def not_found_error(error):
    db.session.rollback()
    return get_error_response(error, 404)


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return get_error_response(error, 500)
