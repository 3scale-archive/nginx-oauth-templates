# Authorization Code / Server-Side Web Applications Flow

## Token Generation

### Requirements

You will need to:

* Install Redis on your Nginx Server (see below for instructions)
* Find all instances of CHANGE_ME in the config files and replace them with the correct values for your API
* Place threescale_utils.lua in /opt/openresty/lualib/threescale_utils.lua

#### Installing Redis

Download and install redis on Nginx server (we use version 2.6.16 which is the currently stable version at the time of writing this)

```
tar zxvf  redis-VERSION.tar.gz  
cd redis-VERSION
make
sudo make install
```

In order to to install and run redis server you will need to run the following, accepting all the default values:

`sudo ./utils/install_server.sh`

### Files

- `authorize.lua` - This file contains the logic for authorizing the client, redirecting the end_user to the oAuth login page, generating the access token and checking that the return url matches the one specified by the API buyer. It runs when the /authorize endpoint is hit.
- `authorized_callback.lua` - This file contains the logic for redirecting an API end user back to the API buyer’s redirect url. As an API provider, you will need to call this endpoint once your user successfully logs in and authorizes the API buyer’s requested access. This file gets executed when the /callback endpoint is called by your application.
- `get_token.lua` - This file contains the logic to return the access token for the client identified by a client_id. It gets executed when the /oauth/token endpoint is called.
- `nginx.conf` - This is a typical Nginx config file. Feel free to edit it or to copy paste it to your existing .conf if you are already running Nginx.
- `nginx.lua` - This file contains the logic that you defined on the web interface to track usage for various metrics and methods as well as checking for authorization to access the various endpoints.

### Usage

To get an authorization code you will need to call the authorize endpoint on the Nginx server, e.g if it's running on localhost you would visit

`https://localhost/authorize?client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground%2F&response_type=code&scope=SCOPE`

If credentials are correct and user grants access, the temporary authorization code will be returned at the redirect_uri specified, e.g if your redirect uri is the google oauth developer playground you will get the code returned as per the below:

`https://developers.google.com/oauthplayground/?code=AUTHORIZATION_CODE&state=STATE_VALUE`

You can then use that temporary code to exchange for an access token by calling the /oauth/token endpoint, e.g

`curl -v -X POST "https://localhost/oauth/token" -d "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&redirect_uri=REDIRECT_URI&code=AUTHORIZATION_CODE&grant_type=authorization_code"` 

## No Token Generation

### Requirements

You will need to:

* Find all instances of CHANGE_ME in the config files and replace them with the correct values for your API
* Place threescale_utils.lua in /opt/openresty/lualib/threescale_utils.lua

_Please note, you will NOT need to install Redis for this flow_

### Files

- `get_token.lua` - This file contains the logic to return the access token for the client identified by a client_id. It gets executed when the /oauth/token endpoint is called.
- `nginx.conf` - This is a typical Nginx config file. Feel free to edit it or to copy paste it to your existing .conf if you are already running Nginx.
- `nginx.lua` - This file contains the logic that you defined on the web interface to track usage for various metrics and methods as well as checking for authorization to access the various endpoints.

### Usage

Since the Token generation is performed by an Authorization Server other than Nginx, you will visit your Authorization Server to get an authorization code first and then request the access_token through the Nginx server by visiting the /oauth/token endpoint, e.g if Nginx is on localhost

`curl -v -X POST "https://localhost/oauth/token" -d "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&redirect_uri=REDIRECT_URI&code=AUTHORIZATION_CODE&grant_type=authorization_code"` 

This will return the access token in the following form:

{"access_token": ACCESS_TOKEN, "expires_in": TTL, "token_type": "bearer", "refresh_token": REFRESH_TOKEN}

If your Authorization Server supports refresh tokens, you can request a new access token by making the following call:

`curl -v -X POST "https://localhost/oauth/token" -d "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&refresh_token=REFRESH_TOKEN&grant_type=refresh_token"` 

### Notes

The files above make the following assumptions about your Authorization Server:

1. Authorization Server supports refresh tokens
2. The parameters that your Authorization Server needs in order to issue authorization codes/access tokens
3. The access tokens have a limited ttl 

If your Authorization Server does not support/match all of the above, you will need to modify the templates accordingly.

