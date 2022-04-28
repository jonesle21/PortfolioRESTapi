from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

import constants
import requests



app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = 'ThisIsTheSecretKey'
app.debug = True


@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id='Am0NdDm5ukWi18VYkKF4Asj6lDYbWDQ9',
    client_secret='ThsPf_X8Ooq8emay0fT7ZC8mnffjTt2XsPwuUJC8I19RZrLWyI85bRKILP1T90EX',
    api_base_url='https://jonesl7-assignment7.us.auth0.com',
    access_token_url='https://jonesl7-assignment7.us.auth0.com/oauth/token',
    authorize_url='https://jonesl7-assignment7.us.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/callback')
def callback_handling():
    info = auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    
    session['JWT'] = info['id_token']
    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    #send GET/users request to API to check if user has been created 
    headers = { 'accept': 'application/json' }
    r = requests.get("https://jonesl7-portfolio-rest.uk.r.appspot.com/users", headers=headers)
    data = r.json()
    in_data = False
    for users in data:
        if users["user_id"] == userinfo["sub"]:
            return redirect('/dashboard')
    body = {'name': userinfo['nickname'],'user_id': userinfo['sub']}
    headers = { 'content-type': 'application/json', 'accept': 'application/json' }
    r = requests.post("https://jonesl7-portfolio-rest.uk.r.appspot.com/users", json=body, headers=headers)
    #send POST/users request to API if user has not been created
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri="https://jonesl7-portfolio-autho.uk.r.appspot.com/callback")


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': 'Am0NdDm5ukWi18VYkKF4Asj6lDYbWDQ9'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.PROFILE_KEY], indent=4),
                           userJWT = session['JWT'] )

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)