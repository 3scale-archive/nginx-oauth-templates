# Client-Side Web Application / Implicit Grant Flow

##Requirements

You will need to install Redis on your Nginx server in order for this to work. You can find instructions on how to do this here:

## Token Generation

Nginx acts as the OAuth provider. 

### Usage

1. Client calls /authorize endpoint to redirect user to login page:

`curl -v -X GET "https://nginx-server/authorize?scope=PLAN_ID&redirect_uri=REDIRECT_URI&response_type=token&client_id=CLIENT_ID`

2. If user grants access, API Auth Server calls /callback endpoint with state and shared_secret 
3. If all is well, Nginx sends access_token to redirect_url 


#### Notes 

## No Token Generation


