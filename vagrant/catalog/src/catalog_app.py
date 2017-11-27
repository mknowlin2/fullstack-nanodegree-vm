#!/usr/bin/env python3
#
# The Catalog Web application.
from flask import Flask, jsonify, request, url_for, abort, g, \
     make_response, render_template
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
from database.data_access import get_users, get_user_by_id, \
     get_user_by_username, add_user, verify_auth_token, \
     get_user_by_email, add_3rd_prty_user

# Import oauth2 libraries
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
#import httplib2
import json
import requests


app = Flask(__name__)
auth = HTTPBasicAuth()

# Setup Client id
CLIENT_ID = json.loads(
                 open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Web Application"


@auth.verify_password
def verify_password(username_or_token, password):
    # Attempt to authenticate token
    user_id = verify_auth_token(username_or_token)

    if user_id:
        user = get_user_by_id(user_id)
    else:
        user = get_user_by_username(username_or_token)
        if not user or not user.verify_password(password):
            return False

    g.user = user
    return True


@app.route('/catalog/login')
def showLogin():
    return render_template('login.html')


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    if provider == 'google':
        # Parse the auth code
        # auth_code = request.json.get('auth_code')
        auth_code = request.data
        print(auth_code)
        # Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secret.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'),
                           401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Get user information
        url = "https://www.googleapis.com/oauth2/v1/tokeninfo"
        params = {'access_token': credentials.access_token}
        result = requests.get(url, params=params)
        result_data = result.json()

        # If there was an error in the access token info, abort.
        if result_data.get('error') is not None:
            response = make_response(json.dumps(result_data.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result_data.get('user_id') != gplus_id:
            response = make_response(
                json.dumps("Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result_data.get('issued_to') != CLIENT_ID:
            response = make_response(
                json.dumps("Token's client ID does not match app's."), 401)
            print ("Token's client ID does not match app's.")
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_access_token = login_session.get('access_token')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already connected.'),
                                     200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store the access token in the session for later use.
        login_session['access_token'] = credentials.access_token
        login_session['gplus_id'] = gplus_id

        # Get user info
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        user = get_user_by_email(email)
        if user is None:
            user = add_3rd_prty_user(name, picture, email)

        # Generate token
        token = user.generate_auth_token()

        # Send back token to the client
        return jsonify({'token': token.decode('ascii')})
    else:
        return jsonify({'message': 'Unrecognizied Provider'})


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/catalog', methods=['GET'])
def showCatalog():
    return render_template('catalog.html')


@app.route('/catalog/user', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        print("Missing arguments")
        abort(400)

    user = get_user_by_username(username)

    if user is not None:
        print('Existing Username')
        return jsonify({'message': 'User already exists'}), 200

    add_user(username, password)
    return jsonify({'message': 'New user added'}), 201


@app.route('/api/v1/user/<int:id>', methods=['GET'])
def get_user(id):
    user = get_user_by_id(id)
    if not user:
        print('Invalid user id provided.')
        return jsonify({'message': 'Invalid user id provided.'}), 200
    return jsonify({'username': user.username})


@app.route('/api/v1/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


if __name__ == '__main__':
    app.secret_key = 'ppa_bew_golatac_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
