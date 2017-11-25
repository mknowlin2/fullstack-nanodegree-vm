#!/usr/bin/env python3
#
# The Catalog Web application.
from flask import Flask, jsonify, request, url_for, abort
from database.data_access import get_users, get_user_by_username, add_user


app = Flask(__name__)


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


if __name__ == '__main__':
    app.secret_key = 'dev_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
