# Authorization Code / Server-Side Web Applications Flow

## Requirements

## Token Generation

### Files

- `authorize.lua` - This file contains the logic for authorizing the client, redirecting the end_user to the oAuth login page, generating the access token and checking that the return url matches the one specified by the API buyer. It runs when the /authorize endpoint is hit.
- `authorized_callback.lua` - This file contains the logic for redirecting an API end user back to the API buyer’s redirect url. As an API provider, you will need to call this endpoint once your user successfully logs in and authorizes the API buyer’s requested access. This file gets executed when the /callback endpoint is called by your application.
- `get_token.lua` - This file contains the logic to return the access token for the client identified by a client_id. It gets executed when the /oauth/token endpoint is called.
- `nginx.conf` - This is a typical Nginx config file. Feel free to edit it or to copy paste it to your existing .conf if you are already running Nginx.
- `nginx.lua` - This file contains the logic that you defined on the web interface to track usage for various metrics and methods as well as checking for authorization to access the various endpoints.

### Usage



## No Token Generation

### Files

### Usage