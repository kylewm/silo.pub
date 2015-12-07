#!/bin/python

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, parse_qs


# Facebook
#ACCESS_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRlX2lzc3VlZCI6IjIwMTUtMTEtMjFUMTg6NTc6MzAuNTQ4MDk3IiwiY2xpZW50X2lkIjoiaHR0cDovL2V4YW1wbGUuY29tLyIsInNpdGUiOjQzLCJzY29wZSI6InBvc3QiLCJtZSI6Imh0dHA6Ly9mZXZlcmRyZWFtLmNjL2ZhY2Vib29rLmNvbS8xMzQzMDc3NTY5MzI5MTkiLCJub25jZSI6MTkxNTg4MDM5N30.sdjM8utyDorgf-Rt2-ia9Vpl7WO7vXNYmVlXXjQxa5E'
# Flickr
ACCESS_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzaXRlIjo1NSwibm9uY2UiOjkyNTEwNjc0OSwic2NvcGUiOiJwb3N0IiwiZGF0ZV9pc3N1ZWQiOiIyMDE1LTExLTIxVDIzOjEyOjU4LjkyNDg5MyIsImNsaWVudF9pZCI6Imh0dHA6Ly9leGFtcGxlLmNvbS8iLCJtZSI6Imh0dHA6Ly9mZXZlcmRyZWFtLmNjL2ZsaWNrci5jb20vMzkyMTY3NjRATjAwIn0.n20Hm5PIWqxhw3XIUN2zJHBXJmF08LL-A47pADNylj4'
MICROPUB_ENDPOINT = 'http://feverdream.cc/micropub'


if __name__ == '__main__':
    r = requests.post(MICROPUB_ENDPOINT, headers={
        'Authorization': 'Bearer ' + ACCESS_TOKEN,
    }, data={
        'name': 'Test post with a photo',
        'category[]': ['https://flickr.com/people/kparks/', 'devils slide',
                       'outdoor', 'highway 1', 'california'],
    }, files={
        'photo': open('/home/kmahan/Pictures/2015/08/23/IMG_4373.JPG', 'rb')
    })

    photo_url = r.headers.get('Location')

    print('Result', r, r.text)
    print('Location', r.headers['Location'])

    r = requests.post(MICROPUB_ENDPOINT, headers={
        'Authorization': 'Bearer ' + ACCESS_TOKEN
    }, data={
        'like-of': 'https://www.flickr.com/photos/kparks/10746970745/in/dateposted/'
    })

    print('Result', r, r.text)
    print('Location', r.headers['Location'])

    r = requests.post(MICROPUB_ENDPOINT, headers={
        'Authorization': 'Bearer ' + ACCESS_TOKEN
    }, data={
        'in-reply-to': photo_url,
        'content': 'Test comment on your photo!'
    })

    print('Result', r, r.text)
    print('Location', r.headers['Location'])
