#!/usr/bin/env python3
#
# The Catalog Web application.
from flask import Flask, jsonify, request, url_for, abort, g
from flask_httpauth import HTTPBasicAuth
from database.data_access import get_users, get_user_by_id, \
     get_user_by_username, add_user


app = Flask(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
    user = get_user_by_username(username)

    if not user or not user.verify_password(password):
        return False

    g.user = user
    return True


@app.route('/user', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        print("Missing arguments")
        abort(400)

    user = get_user_by_username(username)

    if user is not None:
        print('Existing Username')
        return jsonify({'message':'User already exists'}), 200

    add_user(username, password)
    return jsonify({'message': 'New user added'}), 201


@app.route('/api/v1/user/<int:id>', methods=['GET'])
def get_user(id):
    user = get_user_by_id(id)
    if not user:
        print('Invalid user id provided.')
        return jsonify({'message':'Invalid user id provided.'}), 200
    return jsonify({"username": user.username})


@app.route('/api/v1/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })


if __name__ == '__main__':
    app.secret_key = 'dev_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
