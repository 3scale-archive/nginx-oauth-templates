# Client Credentials Flow

The calls for requesting an access token are the same regardless of which server generates and manages the access token (Nginx or an additional Authorization Server.) 

## Requirements

You will need to:

* Find all instances of CHANGE_ME in the config files and replace them with the correct values for your API
* Place threescale_utils.lua in /opt/openresty/lualib/threescale_utils.lua

_Please note, you will NOT need to install Redis for this flow_

## Files

- `get_token.lua` - This file contains the logic to return the access token for the client identified by a client_id. It gets executed when the /oauth/token endpoint is called.
- `nginx.conf` - This is a typical Nginx config file. Feel free to edit it or to copy paste it to your existing .conf if you are already running Nginx.
- `nginx.lua` - This file contains the logic that you defined on the web interface to track usage for various metrics and methods as well as checking for authorization to access the various endpoints.

## Usage

To get an access token you will need to call the oauth/token endpoint on the Nginx server, e.g if it's running on localhost

`curl -v -X POST "https://localhost/oauth/token" -d "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=client_credentials"`

This will return an access token in the following form:

```json
{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}
```

You can then call your API using the access_token instead of the client_id/client_secret

`curl -v -X GET "https://localhost/API_ENDPOINT?access_token=ACCESS_TOKEN"`
