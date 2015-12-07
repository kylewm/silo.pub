#!/bin/python

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, parse_qs


# Twitter
ACCESS_TOKEN = 'd2c5a940493c56e99e1acfa834b69f75'
MICROPUB_ENDPOINT = 'http://feverdream.cc/micropub'


if __name__ == '__main__':
    r = requests.post(MICROPUB_ENDPOINT, data={
        'content': 'Test post without a photo',
        'access_token': ACCESS_TOKEN,
    })

    print('Result', r, r.text)
    print('Location', r.headers['Location'])

    # r = requests.post(MICROPUB_ENDPOINT, headers={
    #     'Authorization': 'Bearer ' + ACCESS_TOKEN
    # }, data={
    #     'name': 'Named Post',
    #     'content': 'Test post with a title',
    # })

    # print('Result', r, r.text)
    # print('Location', r.headers['Location'])

    # r = requests.post(MICROPUB_ENDPOINT, headers={
    #     'Authorization': 'Bearer ' + ACCESS_TOKEN
    # }, data={
    #     'content': 'Test post with a photo',
    # }, files={
    #     'photo': open('/home/kmahan/Pictures/2015/08/23/IMG_4373.JPG', 'rb')
    # })

    # print('Result', r, r.text)
    # print('Location', r.headers['Location'])
