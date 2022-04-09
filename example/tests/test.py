#!/usr/bin/env python3


import json

import requests

LOGIN_API_ENDPOINT = "http://localhost:4000/login"
REFRESH_API_ENDPOINT = "http://localhost:4000/refresh"
REGISTER_API_ENDPOINT = "http://localhost:4000/register"
LOGOFF_API_ENDPOINT = "http://localhost:4000/logout"


def do_auth(username, password, url=LOGIN_API_ENDPOINT) -> dict:
    data = {
        "username": username,
        "password": password
    }

    # sending post request and saving response as response object
    r = requests.post(url=url, json=data)

    print(f"do_auth Code: {r.status_code}, Response: {r.json()}\n")

    # extracting response text
    response_text = r.text
    # pprint(response_text)

    d = json.loads(response_text)

    return d


def do_reg(username, password, email, url=REGISTER_API_ENDPOINT) -> dict:
    data = {
        "username": username,
        "password": password,
        "email": email
    }

    # sending post request and saving response as response object
    r = requests.post(url=url, json=data)

    print(f"do_reg Code: {r.status_code}, Response: {r.json()}\n")

    # extracting response text
    response_text = r.text
    # pprint(response_text)

    d = json.loads(response_text)

    return d


def do_get(url, access_token: str):
    headers = {
        'Authorization': ('Bearer ' + access_token)
    }

    response = requests.get(url, headers=headers)

    return response


def do_post(url, access_token: str, val: json):
    headers = {
        'Authorization': ('Bearer ' + access_token)
    }

    response = requests.post(url, headers=headers, json=val)

    return response


def do_logout(access_token, url=LOGOFF_API_ENDPOINT):
    headers = {
        'Authorization': ('Bearer ' + access_token)
    }

    r = requests.post(url=url, headers=headers, )
    print(r.text)


def do_refresh(refresh_token, url=REFRESH_API_ENDPOINT):
    data = {
        'refresh': refresh_token
    }

    r = requests.post(url=url, data=data)
    print(response)
    d = json.loads(r.text)

    return d


token_dict = do_auth("alexj", "goose")
# check response status code (should be 200 if successful)
# pprint( token_dict)


token = token_dict['access_token']

json = {
    "user_id": "1",
    "title": "my title",
    "body": "my text body"
}

# now I can call the endpoint
response = do_post('http://localhost:4000/todo', token, json)
# check response status code (should be 200 if successful)
print(response)
print(response.status_code)  # error 401 : not authenticated

do_logout(token)

# now I can call the endpoint
response = do_post('http://localhost:4000/todo', token, json)
# check response status code (should be 200 if successful)
print(response)
print(response.status_code)  # error 401 : not authenticated
