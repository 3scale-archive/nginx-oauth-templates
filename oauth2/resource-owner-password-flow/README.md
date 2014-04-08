# Resource Owner Password Flow

Nginx is **NOT** the OAuth provider in this flow. It could potentially be the OAuth provider, but since user details are held by the Provider it makes sense for the API Authorization server to authenticate user and issue the access token. 

## Usage

- Authorize:

`curl -X GET "http://localhost/oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=password&username=USERNAME&password=PASSWORD"`

Returns Access Token from API Auth Server.

You can then call API using the access_token:

`curl -v -X GET "http://localhost/API_ENDPOINT?access_token=ACCESS_TOKEN"`

### Notes 
