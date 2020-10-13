#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import webbrowser
import urllib.parse as urlparse
from urllib.parse import urlencode
import requests
from base64 import  urlsafe_b64encode
import secrets
from hashlib import sha256

from diff import diff

from threading import Thread
import os
from os import path, getcwd
from time import time
import sys
import argparse
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from getpass import getuser

import traceback
import json
from json.decoder import JSONDecodeError
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

epilog='''<https://www.github.com/martinmake/spotify-playlist-manager>'''

client_id = 'ccf29f57a6f049a08d83403ff98ce91b';
redirect_uri = 'http://localhost:8080';

scope = 'playlist-modify-public playlist-modify-private'
state = '0123456789ABCDE'
maximum_track_count_in_block = 100
code: str

host_name = 'localhost'
server_port = 8080

tracks_filepath_default='./tracks.tsv'
value_separator_default='\t'
value_separator=value_separator_default
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

    webbrowser.open( 'https://accounts.spotify.com/authorize' + '?'
                   + urlencode({ 'response_type'         : 'code'
                               , 'client_id'             : client_id
                               , 'scope'                 : scope
                               , 'redirect_uri'          : redirect_uri
                               , 'state'                 : state
                               , 'code_challenge'        : code_challenge
                               , 'code_challenge_method' : 'S256'         })
                   , new=2 )
    t.join()

    return code

def request_tokens():
    code_verifier = secrets.token_urlsafe(43 + secrets.randbits(7) % 86)
    code = request_code(code_verifier )

    response = requests.post( 'https://accounts.spotify.com/api/token'
                            , headers={ 'content-type' : 'application/x-www-form-urlencoded' }
                            , data=urlencode({ 'client_id'     : client_id
                                             , 'grant_type'    : 'authorization_code'
                                             , 'code'          : code
                                             , 'redirect_uri'  : redirect_uri
                                             , 'code_verifier' : code_verifier
                                             }).encode('ascii') )
    return response.json()

def refresh_tokens(refresh_token):
    response = requests.post( 'https://accounts.spotify.com/api/token'
                            , headers={ 'content-type' : 'application/x-www-form-urlencoded' }
                            , data=urlencode({ 'grant_type'    : 'refresh_token'
                                             , 'refresh_token' : refresh_token
                                             , 'client_id'     : client_id
                                             }).encode('ascii') )
    return response.json()

def get_access_token():
    # check cache for valid access token
    try:
        with open(tokens_filepath, 'r') as tokens_file:
            try:
                tokens = json.load(tokens_file)
                if tokens is None: raise TypeError
            except ( JSONDecodeError
                   , TypeError ):
                os.remove(tokens_filepath)
                return get_access_token()
        try:
            if time() - os.path.getmtime(tokens_filepath) > tokens['expires_in']:
                tokens = refresh_tokens(tokens['refresh_token'])
                with open(tokens_filepath, 'w') as tokens_file:
                    json.dump(tokens, tokens_file)
            return tokens['access_token']
        except KeyError:
            os.remove(tokens_filepath)
            return get_access_token()
    except FileNotFoundError:
        try:
            with open(tokens_filepath, 'w') as tokens_file:
                tokens = request_tokens()
                json.dump(tokens, tokens_file)
                return tokens['access_token']
        except FileNotFoundError:
            os.makedirs(cache_dir)
            return get_access_token()
    except:
        traceback.print_exc()

def push(args):
    playlist_name = args.playlist_name

    access_token = get_access_token()

    if not 'playlist_id' in args:
#       GET https://api.spotify.com/v1/me
        response = requests.get( 'https://api.spotify.com/v1/me'
                               , headers={ 'Authorization': f"Bearer {access_token}" } )
        user_id = response.json()['id']

#       GET https://api.spotify.com/v1/users/{user_id}/playlists
        response = requests.get( f"https://api.spotify.com/v1/users/{user_id}/playlists"
                               , headers={ 'Authorization': f"Bearer {access_token}" } )
        playlists = response.json()['items']
        playlist_id = None
        for playlist in playlists:
            if playlist['name'] == playlist_name:
                playlist_id = playlist['id']
        if not playlist_id:
            if args.create_playlist_if_not_found:
                response = requests.post( f"https://api.spotify.com/v1/users/{user_id}/playlists"
                                        , headers={ 'Authorization': f"Bearer {access_token}"
                                                  , 'content-type' : 'application/json' }
                                        , json={'name' : playlist_name} )
                playlist_id = response.json()['id']
            else:
                print(f"ERROR: Playlist '{playlist_name}' not found!")
                exit(2)


#   GET https://api.spotify.com/v1/playlists/{playlist_id}
    response = requests.get( f"https://api.spotify.com/v1/playlists/{playlist_id}"
                           , headers={ 'Authorization': f"Bearer {access_token}" }
                           , params={ 'fields' : 'tracks.total' } )
    track_count = response.json()['tracks']['total']

    old_track_ids = []
    remaining_track_count = track_count
    while remaining_track_count > 0:
        track_count_in_current_block = 0
        if remaining_track_count > maximum_track_count_in_block:
            track_count_in_current_block = maximum_track_count_in_block
        else:
            track_count_in_current_block = remaining_track_count
#       GET https://api.spotify.com/v1/playlists/{playlist_id}/tracks
        response = requests.get( f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks'
                               , headers={ 'Authorization': f"Bearer {access_token}" }
                               , params={ 'fields' : 'items.track(id)'
                                        , 'offset' : track_count - remaining_track_count
                                        , 'limit'  : track_count_in_current_block } )
        for track in (item['track'] for item in response.json()['items']):
            old_track_ids.append(track['id'])
        remaining_track_count -= track_count_in_current_block

    track_ids = []
    tracks_filepath = args.tracks_filepath
    value_separator = args.value_separator
    with open(tracks_filepath, 'r') as tracks_file:
        for track_line in tracks_file.readlines():
            track_id = track_line.split(value_separator)[0].strip()
            if len(track_id) != 22: continue
            track_ids.append(track_id)

    playlist_diff = diff('\n'.join(old_track_ids), '\n'.join(track_ids)).explain().split('\n')
    position = 0
    for track_diff in playlist_diff:
        track_id = track_diff[2:]
        if track_diff.startswith('+'):
            print(f"ADD: {track_id}")
#           POST https://api.spotify.com/v1/playlists/{playlist_id}/tracks
            response = requests.post( f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks" + '?'
                                    + urlencode({ 'uris'     : f"spotify:track:{track_id}"
                                                , 'position' : position })
                                    , headers={ 'Authorization' : f"Bearer {access_token}"
                                              , 'content-type'  : 'application/json' } )
            position += 1
        elif track_diff.startswith('-'):
            print(f"REM: {track_id}")
#           DELETE https://api.spotify.com/v1/playlists/{playlist_id}/tracks
            response = requests.delete( f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks"
                                      , headers={ 'Authorization' : f"Bearer {access_token}"
                                                , 'content-type'  : 'application/json' }
                                      , json={ "tracks": [{ "uri"       : f"spotify:track:{track_id}"
                                                          , "positions" : [position] }] } )
            position = position
        else:
            print(f"SKP: {track_id}")
            position += 1

def pull(args):
    playlist_name = args.playlist_name

    access_token = get_access_token()

    if not 'playlist_id' in args:
#       GET https://api.spotify.com/v1/me
        response = requests.get( 'https://api.spotify.com/v1/me'
                               , headers={ 'Authorization': f"Bearer {access_token}" } )
        user_id = response.json()['id']

#       GET https://api.spotify.com/v1/users/{user_id}/playlists
        response = requests.get( f"https://api.spotify.com/v1/users/{user_id}/playlists"
                               , headers={ 'Authorization': f"Bearer {access_token}" } )
        playlists = response.json()['items']
        playlist_id = None
        for playlist in playlists:
            if playlist['name'] == playlist_name:
                playlist_id = playlist['id']
        if not playlist_id:
            print(f"ERROR: Playlist '{playlist_name}' not found!")
            exit(2)


#   GET https://api.spotify.com/v1/playlists/{playlist_id}
    response = requests.get( f"https://api.spotify.com/v1/playlists/{playlist_id}"
                           , headers={ 'Authorization': f"Bearer {access_token}" }
                           , params={ 'fields' : 'tracks.total' } )
    track_count = response.json()['tracks']['total']

    remaining_track_count = track_count
    print(f"id{value_separator}artists{value_separator}album{value_separator}name")
    while remaining_track_count > 0:
        track_count_in_current_block = 0
        if remaining_track_count > maximum_track_count_in_block:
            track_count_in_current_block = maximum_track_count_in_block
        else:
            track_count_in_current_block = remaining_track_count
#       GET https://api.spotify.com/v1/playlists/{playlist_id}/tracks
        response = requests.get( f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks'
                               , headers={ 'Authorization': f"Bearer {access_token}" }
                               , params={ 'fields' : 'items.track(id,name,artists(name),album(name))'
                                        , 'offset' : track_count - remaining_track_count
                                        , 'limit'  : track_count_in_current_block } )
        for track in (item['track'] for item in response.json()['items']):
            print(track['id'], end=value_separator)
            print(track['artists'][0]['name'], end='')
            for artist in track['artists'][1:]:
                print(', ' + artist['name'], end='')
            print('', end=value_separator)
            print(track['album']['name'], end=value_separator)
            print(track['name'])
        remaining_track_count -= track_count_in_current_block

def main(argv):
    parser = ArgumentParser( prog=argv[0]
                           , description='''      Push/pull spotify playlist
                                            from text file to cloud and vice versa.'''
                           , epilog=epilog
                           , formatter_class=ArgumentDefaultsHelpFormatter
                           , allow_abbrev=False )
    subparsers = parser.add_subparsers( dest='command'
                                      , required=True
                                      , title='commands'
                                      , description='Select from different commands.'
                                      , help='Idkkkkk.' )

    pull_parser = subparsers.add_parser( 'pull'
                                       , help       ='Pull spotify playlist from the cloud into a file.'
                                       , description='Pull spotify playlist from the cloud into a file.'
                                       , epilog=epilog
                                       , formatter_class=ArgumentDefaultsHelpFormatter
                                       , allow_abbrev=False )
    pull_parser.set_defaults(command=pull)
    pull_parser.add_argument( '-u'
                            , '--username'
                            , type=str
                            , default=getuser()
                            , help='username of current client' )
    pull_parser.add_argument( '-p', '--playlist-name'
                            , type=str
                            , default=path.basename(getcwd())
                            , help='name of your spotify playlist' )
    pull_parser.add_argument( '--port'
                            , type=int
                            , default=8080
                            , choices=[8080, 8888, 123456, 666]
                            , help='local port for authentication' )

    push_parser = subparsers.add_parser( 'push'
                                       , help       ='Push spotify playlist from a file into the cloud.'
                                       , description='Push spotify playlist from a file into the cloud.'
                                       , epilog=epilog
                                       , formatter_class=ArgumentDefaultsHelpFormatter
                                       , allow_abbrev=False )
    push_parser.set_defaults(command=push)
    push_parser.add_argument( '-u', '--username'
                            , type=str
                            , default=getuser()
                            , help='Username of current client.' )
    push_parser.add_argument( '-f', '--tracks-filepath'
                            , type=str
                            , default=tracks_filepath_default
                            , help='Path to tracks file.' )
    push_parser.add_argument( '-s', '--value-separator'
                            , type=str
                            , default='|'
                            , help='Value separator used in the tracks file.' )
    push_parser.add_argument( '-p', '--playlist-name'
                            , type=str
                            , default=path.basename(getcwd())
                            , help='Name of your spotify playlist.' )
    push_parser.add_argument( '-c', '--create-playlist-if-not-found'
                            , action='store_true'
                            , help="If the playlist isn't be found, new one will be created." )
    push_parser.add_argument( '--port'
                            , type=int
                            , default=8080
                            , choices=[8080, 8888, 123456, 666]
                            , help='Local port for authentication.' )
    args = parser.parse_args()
    global server_port # retarded
    server_port = args.port
    args.command(args)

if __name__ == "__main__":
    main(sys.argv)
