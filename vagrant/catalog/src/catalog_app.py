#!/usr/bin/env python3
#
# The Catalog Web application.
from flask import Flask, redirect, request, url_for, abort, g, \
     jsonify, make_response, render_template, flash
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
from database.data_access import get_users, get_user_by_id, \
     get_user_by_username, add_user, verify_auth_token, \
     get_user_by_email, add_3rd_prty_user

# Import oauth2 libraries
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import random
import string


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
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


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


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if provider == 'internal':
        login_session['provider'] = 'internal'
        verified = verify_password(request.form['username'],
                        request.form['password'])

        if verified == True:
            login_session['username'] = g.user.username
            login_session['picture'] = g.user.picture
            login_session['email'] = g.user.email
            login_session['user_token'] = g.user.generate_auth_token()

            print('username: {}'.format(login_session['username']))
            print('picture: {}'.format(login_session['picture']))
            print('email: {}'.format(login_session['email']))
            print('user_token: {}'.format(login_session['user_token']))

            return redirect(url_for('showCatalog'))
        else:
            flash("Username and password are invalid.")
            return redirect(url_for('showLogin'))

        return jsonify({'message': 'Internal Provider'})

    if provider == 'google':
        login_session['provider'] = 'google'

        # Obtain authorization code
        auth_code = request.data

        # Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secret.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(
                                     json.dumps('Failed to upgrade the \
                                                authorization code.'),
                                     401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = 'https://www.googleapis.com/oauth2/v1/tokeninfo'
        result = requests.post(url,
                               params={'access_token': access_token},
                               headers={'content-type':
                                        'application/x-www-form-urlencoded'})

        result = result.json()

        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result
                                                .get('error_description')),
                                     500)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result.get('user_id') != gplus_id:
            response = make_response(
                                     json.dumps(
                                                "Token's user ID doesn't \
                                                match given user ID."),
                                     401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result.get('issued_to') != CLIENT_ID:
            response = make_response(
                                     json.dumps("Token's client ID does \
                                                not match app's."), 401)
            print("Token's client ID does not match app's.")
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_access_token = login_session.get('access_token')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            print("Current user is already connected.")
            response = make_response(json.dumps('Current user is already \
                                                connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store the access token in the session for later use.
        # login_session['access_token'] = credentials.access_token
        login_session['access_token'] = access_token
        login_session['gplus_id'] = gplus_id

        # Get user info
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']

        user = get_user_by_email(login_session['email'])

        if user is None:
            user = add_3rd_prty_user(login_session['username'],
                                     login_session['picture'],
                                     login_session['email'])

        # Generate token
        token = user.generate_auth_token()
        login_session['user_token'] = token

        print('username: {}'.format(login_session['username']))
        print('picture: {}'.format(login_session['picture']))
        print('email: {}'.format(login_session['email']))
        print('user_token: {}'.format(login_session['user_token']))

        # Send back token to the client
        # return jsonify({'token': token.decode('ascii')})
        return 'Success'
    else:
        return jsonify({'message': 'Unrecognizied Provider'})


@app.route('/disconnect')
def disconnect():
    print('login_session[provider]: {}'.format(login_session.get('provider')))
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_token']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


@app.route('/gdisconnect')
def gdisconnect():
    print('access_token: {}'.format(login_session.get('access_token')))

    # Only disconnect a connected user.
    if 'access_token' not in login_session:
        response = make_response(json.dumps(
                                 'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = login_session['access_token']

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
                           params={'token': access_token},
                           headers={'content-type':
                                    'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')

    if status_code == 200:
        del login_session['access_token']
        del login_session['gplus_id']
        response = make_response(json.dumps(
                                 'Credentials successfully revoked.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
                                 'Failed to revoke token for given user.',
                                 400))
        response.headers['Content-Type'] = 'application/json'
        return response


if __name__ == '__main__':
    app.secret_key = 'ppa_bew_golatac_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
