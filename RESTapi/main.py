from google.cloud import datastore
from flask import Flask, jsonify, _request_ctx_stack,Response
from flask import request
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
import urllib.parse

import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask, make_response
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'ThisIsTheSecretKey'
app.debug = True

client = datastore.Client()

BOATS = "boats"
LOADS = "loads"
USERS = 'users'

# Update the values of the following 3 variables
CLIENT_ID = 'Am0NdDm5ukWi18VYkKF4Asj6lDYbWDQ9'
CLIENT_SECRET = 'ThsPf_X8Ooq8emay0fT7ZC8mnffjTt2XsPwuUJC8I19RZrLWyI85bRKILP1T90EX'
DOMAIN = 'jonesl7-assignment7.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

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

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

@app.route('/')
def index():
    return "Please navigate to /boats to use this API"\

@app.route('/users', methods=['POST', 'GET'])
def users_get_post():
    if request.method == 'POST':
        content = request.get_json()
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update({"name": content["name"],"user_id": content["user_id"]})
        client.put(new_user)
        user_key = client.key(USERS, new_user.key.id)
        user = client.get(key=user_key)
        client.put(user)
        user["id"] = new_user.key.id
        if "application/json" in request.accept_mimetypes:
            return (json.dumps(user), 201)
        else:
            return ('', 406)
    elif request.method == 'GET':
        query = client.query(kind=USERS)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
        if "application/json" in request.accept_mimetypes:
            return json.dumps(results), 200
        else:
            return ('', 406)
    else:
        return jsonify(error='Method not recogonized')

# Create a boat if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(BOATS))
        new_boat.update({"name": content["name"], "type": content["type"],
        "length": content["length"], "owner": payload["sub"], "loads": []})
        client.put(new_boat)
        boat_key = client.key(BOATS, new_boat.key.id)
        boat = client.get(key=boat_key)
        client.put(boat)
        boat["id"] = new_boat.key.id #adding values that aren't in datastore
        boat["self"] = request.url_root + "boats/" + str(new_boat.key.id)
        if "application/json" in request.accept_mimetypes:
            return json.dumps(boat), 201
        else:
            return ('', 406)
    elif request.method == 'GET':
        payload = verify_jwt(request)
        count = 0
        query = client.query(kind=BOATS)
        countResults = query.fetch()
        for en in countResults:
            count += 1
        query = client.query(kind=BOATS)
        owner = payload["sub"]
        query = query.add_filter('owner', '=', owner)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + "boats/" + str(e.key.id)
        output = {"total boats": count, "boats": results}
        if next_url:
            output["next"] = next_url
        if "application/json" in request.accept_mimetypes:
            res = make_response(json.dumps(output))
            res.mimetype = 'application/json'
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res
        else:
            return ('', 406)
    else:
        return jsonify(error='Method not recogonized')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload  
    

@app.route('/boats/<id>', methods=['DELETE', 'GET', 'PUT', 'PATCH'])        
def boat_CRUD(id):
    if request.method == 'DELETE':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            key = client.key("boats", int(id))
            boat = client.get(key=key)
            if boat != None:
                if boat["owner"] == payload["sub"]:
                    #removing loads from boat if a boat is getting deleted
                    if boat["loads"] != []:
                        for loads in boat["loads"]:
                            load_key = client.key(LOADS, loads["id"])
                            load = client.get(key=load_key)
                            load["carrier"] = None
                            client.put(load)
                    client.delete(key)
                    return json.dumps({"success":"boat deleted"}),204
                else:
                    return json.dumps({"error":"owner doesn't match"}), 403
            else:
                return json.dumps({"Error": "No boat with this boat_id exists"}), 404
        else:
            return '',406
    elif request.method == 'PUT' or request.method == 'PATCH':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            content = request.get_json()
            if "name" in content and "type" in content and "length" in content:
                boat_key = client.key('boats', int(id))
                boat = client.get(key=boat_key)
                if boat != None:
                    if boat["owner"] == payload["sub"]:
                        boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
                        client.put(boat)
                        boat["id"] = boat.key.id
                        boat["self"] = request.base_url
                        return (json.dumps(boat), 200)
                    else:
                        return json.dumps({"error":"owner doesn't match"}), 403
                else:
                    return (json.dumps({"Error": "No boat with this boat_id exists"}), 404) 
        else:
            return '',406            
    elif request.method == 'GET':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            key = client.key("boats", int(id))
            boat = client.get(key=key)
            if boat != None:
                if boat["owner"] == payload["sub"]:
                    boat["id"] = boat.key.id #adding values that aren't in datastore
                    boat["self"] = request.url_root + "boats/" + str(boat.key.id)
                    return json.dumps(boat), 200
                else:
                    return json.dumps({"error":"owner doesn't match"}), 403
            else:
                return json.dumps({"Error": "No boat with this boat_id exists"}), 404 
        else:
            return '',406
    else:
        return json.dumps({"error": "boat is null"}), 403

@app.route('/boats/<boat_id>/loads/<load_id>', methods=['DELETE', 'PUT'])
def boats_loads_CRUD(boat_id, load_id):
    if request.method == 'PUT':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            key = client.key("boats", int(boat_id))
            boat = client.get(key=key)
            if boat != None:
                if boat["owner"] == payload["sub"]:
                    load_key = client.key(LOADS, int(load_id))
                    load = client.get(key=load_key)
                    if load_id in boat["loads"]:
                        return json.dumps({"error:" "load already added to boat"}), 403
                    else:
                        if load != None:
                            if load["carrier"] is None:
                                load.update({"carrier": int(boat_id)})
                                client.put(load)
                                load["id"] = load.key.id
                                load["self"] = request.url_root + "loads/" + str(load.key.id)
                                boat["loads"].append(load)
                                client.put(boat)
                                boat["id"] = boat.key.id #adding values that aren't in datastore
                                boat["self"] = request.url_root + "boats/" + str(boat.key.id)
                                return json.dumps(boat), 204
                            else:
                                return json.dumps({"error": "Load already has boat"}), 403
                        else:
                            return json.dumps({"error": "No load with this load id exists"}), 404 
                else:
                    return json.dumps({"error":"owner doesn't match"}), 403
            else:
                return json.dumps({"Error": "No boat with this boat_id exists"}), 404
        else:
            return '',406
    elif request.method == 'DELETE':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            key = client.key("boats", int(boat_id))
            boat = client.get(key=key)
            if boat != None:
                if boat["owner"] == payload["sub"]:
                    load_key = client.key(LOADS, int(load_id))
                    load = client.get(key=load_key)
                    if load_id in boat["loads"]:
                        return json.dumps({"error:" "load already added to boat"}), 403
                    else:
                        if load != None:
                            if load["carrier"] == int(boat_id):
                                for loads in boat["loads"]:
                                    if loads["id"] == int(load_id):
                                        boat["loads"].remove(loads)
                                    boat.update({"loads": boat["loads"]})
                                client.put(boat)
                                boat["id"] = boat.key.id #adding values that aren't in datastore
                                boat["self"] = request.url_root + "boats/" + str(boat.key.id)
                                load["carrier"] = None
                                client.put(load)
                                return json.dumps(boat), 204
                            else:
                                return json.dumps({"error": "Load does not belong to this boat"}), 403
                        else:
                            return json.dumps({"error": "No load with this load id exists"}), 404 
                else:
                    return json.dumps({"error":"owner doesn't match"}), 403
            else:
                return json.dumps({"Error": "No boat with this boat_id exists"}), 404 
        else:
            return '',406 
    else:
        return jsonify(error='Method not recogonized')   

@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():
    if request.method == 'POST':
        if "application/json" in request.accept_mimetypes:
            content = request.get_json()
            new_load = datastore.entity.Entity(key=client.key(LOADS))
            new_load.update({"volume": content["volume"], "carrier": None, "content": content["content"], "creation_date": content["creation_date"]})
            client.put(new_load)
            load_key = client.key(LOADS, new_load.key.id)
            load = client.get(key=load_key)
            load["id"] = new_load.key.id #adding values that aren't in datastore 
            load["self"] = request.url_root + "loads/" + str(new_load.key.id)
            return json.dumps(load), 201  
        else:
            return '',406
    elif request.method == 'GET':
        if "application/json" in request.accept_mimetypes:
            count = 0
            query = client.query(kind=LOADS)
            countResults = query.fetch()
            for e in countResults:
                count += 1
            query = client.query(kind=LOADS)
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit= q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.url_root + "boats/" + str(e.key.id)
            output = {"total loads": count,"loads": results}
            if next_url:
                output["next"] = next_url
            res = make_response(json.dumps(output))
            res.mimetype = 'application/json'
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res

        else:
            return '',406
    else:
        return jsonify(error='Method not recogonized')

@app.route('/loads/<id>', methods=['GET', 'DELETE', 'PATCH','PUT'])
def loads_CRUD(id):
    if request.method == 'DELETE':
        if "application/json" in request.accept_mimetypes:
            load_key = client.key("loads", int(id))
            load = client.get(key=load_key)
            if load != None:
                if load["carrier"] is None:
                    client.delete(load_key)
                    return 204
                if load["carrier"] != None:
                    boat_id = load["carrier"]
                    query = client.query(kind=BOATS) 
                    results = list(query.fetch())
                    for boats in results:
                        if boats["loads"] != []:
                            for loads in boats["loads"]:
                                if loads["id"] == int(id):
                                    boats["loads"].remove(loads)
                                    boats["loads"] = boats["loads"] 
                                    client.put(boats)            
                    client.delete(load_key)
                    return json.dumps(boat_id), 204
            else:
                return json.dumps({"Error": "No load with this load_id exists"}), 404
        else:
            return '',406
    elif request.method == 'PUT' or request.method == 'PATCH':
        if "application/json" in request.accept_mimetypes:
            key = client.key(LOADS, int(id))
            load = client.get(key=key)
            content = request.get_json()
            if load != None:
                load.update({"volume": content["volume"], "content": content["content"], "creation_date": content["creation_date"]})
                client.put(load)
                load["id"] = load.key.id #adding values that aren't in datastore
                load["self"] = request.url_root + "loads/" + str(load.key.id)
                if load["carrier"] is None:
                    return json.dumps(load), 200
                else:
                    boat_id = load["carrier"]
                    boat_key = client.key(BOATS, boat_id)
                    boat = client.get(key=boat_key)
                    if boat != None:
                        for loads in boat["loads"]:
                            if loads["id"] == int(id):
                                boat["loads"]= load
                            boat["loads"] = boat["loads"]
                        client.put(boat) 
                    return json.dumps(load), 200 
            else:
                return json.dumps({"Error": "No load with this load_id exists"}), 404
        else:
            return '',406
    elif request.method == 'GET':
        if "application/json" in request.accept_mimetypes:
            key = client.key(LOADS, int(id))
            load = client.get(key=key)
            if load != None:
                load["id"] = load.key.id
                load["self"] = request.url_root + "loads/" + str(load.key.id)
                return json.dumps(load), 200
            else:
                return json.dumps({"Error": "No load with this load_id exists"}), 404
        else:
            return '',406
    else:
        return jsonify(error='Method not recogonized')
    
    

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':'Am0NdDm5ukWi18VYkKF4Asj6lDYbWDQ9',
            'client_secret':'ThsPf_X8Ooq8emay0fT7ZC8mnffjTt2XsPwuUJC8I19RZrLWyI85bRKILP1T90EX'
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://jonesl7-assignment7.us.auth0.com/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

