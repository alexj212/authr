
# ------------------------------------
POST http://localhost:4000/register
{
  "password": "goose",
  "username": "alexj",
  "email": "alex@jeannopoulos.com"
}
HTTP/1.1 200


[Asserts]
jsonpath "$['access_token']" exists
jsonpath "$['refresh_token']" exists
[Captures]
ACCESS_TOKEN: jsonpath "$['access_token']"
refresh_token: jsonpath "$['refresh_token']"


# ------------------------------------
POST http://localhost:4000/login
{
  "password": "goose",
  "username": "alexj"
}
HTTP/1.1 200


[Asserts]
jsonpath "$['access_token']" exists
jsonpath "$['refresh_token']" exists
[Captures]
ACCESS_TOKEN: jsonpath "$['access_token']"
refresh_token: jsonpath "$['refresh_token']"

# ------------------------------------
POST http://localhost:4000/todo
Authorization: Bearer BAD_TOKEN
{
  "user_id": "1",
  "title": "my title",
  "body": "my text body"
}
HTTP/1.1 401

# ------------------------------------
POST http://localhost:4000/todo
Authorization: Bearer {{ACCESS_TOKEN}}
{
  "user_id": "1",
  "title": "my title",
  "body": "my text body"
}
HTTP/1.1 201
[Asserts]
status == 201
header "Content-Type" contains "application/json"