#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import webbrowser
import asyncio
import urllib.parse as urlparse
from urllib.parse import urlencode
import requests
from base64 import b64encode

import json
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

client_id = 'ccf29f57a6f049a08d83403ff98ce91b';
client_secret = 'f54a9f2396ac4407b14120e77d63b50d';
redirect_uri = 'http://localhost:8080';

OAuth_url = 'https://accounts.spotify.com/authorize'
token_url = 'https://accounts.spotify.com/api/token'
response_type = 'code'
scope = 'user-read-private user-read-email'
grant_type = 'authorization_code'
state = '0123456789ABCDE'
code: str
access_token: str
refresh_token: str
user_id: str
playlist_name: str = '\u0420\u0415\u0419\u0412' # RAVE # Shouldn't be hard coded!
playlist_id:str

host_name = 'localhost'
server_port = 8080


closer_webpage = \
"""
<!DOCTYPE html>
<html>
    <head>
        <title>You may close this window.</title>
    </head>
    <body>
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

async def one_time_serve():
    server = HTTPServer((host_name, server_port), HTTPRequestHandler)

    try:
        server.handle_request()
    except KeyboardInterrupt:
        server.server_close()

def webbrowse(url):
    wb = webbrowser.get(using="firefox")
    wb.open(url, new=2)
#     webbrowser.open(url, new=2)

def dump_as_json(str):
    json_obj = json.loads(str)
    json_str = json.dumps(json_obj, indent=4, sort_keys=True)
    print(highlight(json_str, JsonLexer(), TerminalFormatter()))


async def main():
    server = one_time_serve()
    webbrowse( OAuth_url + '?' \
             + urlencode({ 'response_type' : response_type \
                         , 'client_id'     : client_id     \
                         , 'scope'         : scope         \
                         , 'redirect_uri'  : redirect_uri  \
                         , 'state'         : state         }))
    await server

    auth = b64encode(str(f'{client_id}:{client_secret}').encode('ascii') \
                    ).decode('ascii')
    response = requests.post( token_url                                                         \
                            , headers={ 'content-type' : 'application/x-www-form-urlencoded'    \
                                      , 'Authorization' : f'Basic {auth}' }                     \
                            , data=urlencode({ 'code'         : code                            \
                                             , 'redirect_uri' : redirect_uri                    \
                                             , 'grant_type'   : grant_type   }).encode('ascii') )
    dump_as_json(response.text)
    response = response.json()
    access_token = response['access_token']
    refresh_token = response['refresh_token']

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
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
