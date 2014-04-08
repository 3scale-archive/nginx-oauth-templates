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

### Usage

1. Client calls /authorize endpoint to redirect user to login page:

`curl -v -X GET "https://nginx-server/authorize?scope=PLAN_ID&redirect_uri=REDIRECT_URI&response_type=token&client_id=CLIENT_ID`

2. If user grants access, API Auth Server calls /callback endpoint with state and shared_secret 
3. If all is well, Nginx sends access_token to redirect_url 


#### Notes 


