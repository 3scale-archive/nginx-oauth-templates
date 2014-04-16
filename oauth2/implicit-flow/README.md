# Client-Side Web Application / Implicit Grant Flow

##Requirements

You will need to:

* Find all instances of CHANGE_ME in the config files and replace them with the correct values for your API
* Place threescale_utils.lua in /opt/openresty/lualib/threescale_utils.lua

You will need to install Redis on your Nginx server in order for this to work:

### Redis

Download and install redis on Nginx server (we use version 2.6.16 which is the currently stable version at the time of writing this)

```
tar zxvf  redis-VERSION.tar.gz  
cd redis-VERSION
make
sudo make install
```

In order to to install and run redis server you will need to run the following, accepting all the default values:

```
sudo ./utils/install_server.sh
```

## Token Generation

Nginx acts as the OAuth provider. 

### Files

- `authorize.lua` - This file contains the logic for authorizing the client and redirecting the end user to the oAuth login page as well as checking that the return url matches the one specified by the API buyer. It gets executed when the /authorize endpoint is hit.
- `authorized_callback.lua` - This file contains the logic for generating the access_token and redirecting back to the application’s redirect url with the access_token. As an API provider, you will need to call this endpoint once your user successfully logs in and authorizes the API buyer’s requested access. This file gets executed when the /callback endpoint is called by your application.
- `nginx.conf` - This is a typical Nginx config file. Feel free to edit it or to copy paste it to your existing .conf if you are already running Nginx.
- `nginx.lua` - This file contains the logic that you defined on the web interface to track usage for various metrics and methods as well as checking for authorization to access the various endpoints.

### Usage

1. Client calls /authorize endpoint to redirect user to login page:

`curl -v -X GET "https://nginx-server/authorize?scope=PLAN_ID&redirect_uri=REDIRECT_URI&response_type=token&client_id=CLIENT_ID`

2. If user grants access, API Auth Server calls /callback endpoint with state and shared_secret 
3. If all is well, Nginx sends access_token to redirect_url 


#### Notes 


