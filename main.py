#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import webbrowser
import urllib.parse as urlparse
from urllib.parse import urlencode
import requests
from base64 import  urlsafe_b64encode
import secrets
from hashlib import sha256

from threading import Thread
import os
from time import time

import traceback
import json
from json.decoder import JSONDecodeError
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

client_id = 'ccf29f57a6f049a08d83403ff98ce91b';
redirect_uri = 'http://localhost:8080';

OAuth_url = 'https://accounts.spotify.com/authorize'
token_url = 'https://accounts.spotify.com/api/token'
scope = 'user-read-private'
state = '0123456789ABCDE'
code: str
access_token: str
refresh_token: str
user_id: str
playlist_name: str = '\u0420\u0415\u0419\u0412' # RAVE # Shouldn't be hard coded!
playlist_id:str

host_name = 'localhost'
server_port = 8080

project_name = 'spotify-playlist-manager'
cache_dir = os.path.expanduser(f"~/.cache/{project_name}")
tokens_filepath = os.path.join(cache_dir, 'tokens.json')


closer_webpage = \
"""
<!DOCTYPE html>
<html>
    <head>
        <title>You may close this window.</title>
    </head>
    <body>
        <h1>You may close this window.</h1>
        <script>close()</script>
    </body>
</html>
"""

class HTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        url = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(url.query)
        if 'code' in qs:
            global code
            code = qs['code'][0]

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(closer_webpage, "utf-8"))

    def log_message(self, format, *args):
        return

def dump_as_json(str):
    json_obj = json.loads(str)
    json_str = json.dumps(json_obj, indent=4, sort_keys=True)
    print(highlight(json_str, JsonLexer(), TerminalFormatter()))

def dump_json(json_obj):
    json_str = json.dumps(json_obj, indent=4, sort_keys=True)
    print(highlight(json_str, JsonLexer(), TerminalFormatter()))

def serve_closer():
    server = HTTPServer((host_name, server_port), HTTPRequestHandler)

    try:
        server.handle_request()
    except KeyboardInterrupt:
        server.server_close()


def request_code(code_verifier ):
    code_challenge = urlsafe_b64encode(sha256(code_verifier.encode('ascii')).digest()).decode('ascii').replace('=','')

    t = Thread(target=serve_closer)
    t.start()

    webbrowser.open( OAuth_url + '?' \
                   + urlencode({ 'response_type'         : 'code'         \
                               , 'client_id'             : client_id      \
                               , 'scope'                 : scope          \
                               , 'redirect_uri'          : redirect_uri   \
                               , 'state'                 : state          \
                               , 'code_challenge'        : code_challenge \
                               , 'code_challenge_method' : 'S256'         })
                   , new=2 )
    t.join()

    return code

def request_tokens():
    code_verifier = secrets.token_urlsafe(43 + secrets.randbits(7) % 86)
    code = request_code(code_verifier )

    response = requests.post( token_url \
                            , headers={ 'content-type' : 'application/x-www-form-urlencoded' } \
                            , data=urlencode({ 'client_id'     : client_id            \
                                             , 'grant_type'    : 'authorization_code' \
                                             , 'code'          : code                 \
                                             , 'redirect_uri'  : redirect_uri         \
                                             , 'code_verifier' : code_verifier        }).encode('ascii') )
    return response.json()

def get_new_access_token(refresh_token):
    response = requests.post( token_url \
                            , headers={ 'content-type' : 'application/x-www-form-urlencoded' } \
                            , data=urlencode({ 'grant_type'    : 'authorization_code' \
                                             , 'refresh_token' : refresh_token        \
                                             , 'client_id'     : client_id            }).encode('ascii') )
    return response.json()['access_token']

def get_access_token():
    # check cache for valid access token
    try:
        with open(tokens_filepath, 'r') as tokens_file:
            try:
                tokens = json.load(tokens_file)
                if tokens is not dict: raise TypeError
                print(tokens)
                if time() - os.path.getmtime(tokens_filepath) > tokens['expires_in']:
                    tokens = get_new_access_token(tokens['refresh_token'])
                    with open(tokens_filepath, 'w') as tokens_file:
                        tokens = request_tokens()
                        json.dump(tokens, tokens_file)
                    return tokens['access_token']
                else: return tokens['access_token']
            except ( JSONDecodeError \
                   , KeyError        \
                   , TypeError       ):
                os.remove(tokens_filepath)
                return get_access_token()
    except FileNotFoundError:
        try:
            with open(tokens_filepath, 'w') as tokens_file:
                tokens = request_tokens()
                dump_json(tokens)
                json.dump(tokens, tokens_file)
                return tokens['access_token']
        except FileNotFoundError:
            os.makedirs(cache_dir)
            return get_access_token()
    except:
        traceback.print_exc()

def main():
    access_token = get_access_token()

#   GET https://api.spotify.com/v1/me
    response = requests.get( 'http://api.spotify.com/v1/me'                        \
                           , headers={ 'Authorization': f'Bearer {access_token}' } )
    dump_as_json(response.text)
    response = response.json()
    user_id = response['id']

#   GET https://api.spotify.com/v1/users/{user_id}/playlists
    response = requests.get( f'https://api.spotify.com/v1/users/{user_id}/playlists' \
                           , headers={ 'Authorization': f'Bearer {access_token}' }   )
    dump_as_json(response.text)
    playlists = response.json()['items']
    for playlist in playlists:
        if playlist['name'] == playlist_name:
            global playlist_id
            playlist_id = playlist['id']

#   GET https://api.spotify.com/v1/playlists/{playlist_id}/tracks
    response = requests.get( f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks'    \
                           , headers={ 'Authorization': f'Bearer {access_token}' }           \
                           , params={ 'fields' : 'items.track(id,name,artists(id,name),album(id,name))' })
    dump_as_json(response.text)
    items = response.json()['items']
    for track in (item['track'] for item in items):
        for artist in track['artists']:
            print(artist['id'] ,end=':')
        print(track['album']['id'], end=':')
        print(track['id'], end='')

        print(' - ', end='')

        print(track['artists'][0]['name'], end='')
        for artist in track['artists'][1:]:
            print(', ' + artist['name'], end='')
        print(' ', end='')
        print(f"[{track['album']['name']}]", end=' ')
        print(track['name'])

if __name__ == "__main__":
    main()
