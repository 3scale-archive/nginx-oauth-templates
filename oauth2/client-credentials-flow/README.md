# Client Credentials Flow

## Requirements

You will need to:

* Find all instances of CHANGE_ME in the config files and replace them with the correct values for your API
* Place threescale_utils.lua in /opt/openresty/lualib/threescale_utils.lua

_Please note, you will NOT need to install Redis for this flow_

## Usage

To get an access token you will need to call the oauth/token endpoint on the Nginx server, e.g if it's running on localhost

`curl -v -X POST "http://localhost/oauth/token" -d "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=client_credentials"`

This will return an access token in the following form:

```json
{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}
```

You can then call your API using the access_token instead

`curl -v -X GET "http://localhost/API_ENDPOINT?access_token=ACCESS_TOKEN"`