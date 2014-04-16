# Resource Owner Password Flow

Nginx is **NOT** the OAuth provider in this flow. It could potentially be the OAuth provider, but since user details are held by the Provider it makes sense for the API Authorization server to authenticate user and issue the access token. 

## Requirements

You will need to:

* Find all instances of CHANGE_ME in the config files and replace them with the correct values for your API
* Place threescale_utils.lua in /opt/openresty/lualib/threescale_utils.lua

## Files

- `get_token.lua` - This file contains the logic to return the access token for the client identified by a client_id. It gets executed when the /oauth/token endpoint is called.
- `nginx.conf` - This is a typical Nginx config file. Feel free to edit it or to copy paste it to your existing .conf if you are already running Nginx.
- `nginx.lua` - This file contains the logic that you defined on the web interface to track usage for various metrics and methods as well as checking for authorization to access the various endpoints.

## Usage

- Authorize:

`curl -X GET "https://localhost/oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=password&username=USERNAME&password=PASSWORD"`

Returns Access Token from API Auth Server.

- You can then call API using the access_token:

`curl -v -X GET "https://localhost/API_ENDPOINT?access_token=ACCESS_TOKEN"`

### Notes 
