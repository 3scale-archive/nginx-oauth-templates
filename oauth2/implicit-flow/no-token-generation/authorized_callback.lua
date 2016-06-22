-- authorized_callback.lua

-- Once the client has been authorized by the API provider in their
-- login, the provider sends the token to the Gateway for storage.
-- The Gateway will then send the token on to the client
local ts = require 'threescale_utils'
local redis = require 'resty.redis'
local red = redis:new()

-- The authorization server should send some data in the callback response to let the
-- API Gateway know which user to associate with the token. 
-- We assume that this data will be sent as uri params. 
-- Additionally, the shared secret between 3scale and the Authorization code should be sent 
-- to authenticate the API against the Gateway.
-- This function should be over-ridden depending on authorization server implementation.
function extract_params()
  local params = {}
  local uri_params = ngx.req.get_uri_args()

  params.user_id = uri_params.user_id or uri_params.username 
  params.state = uri_params.state  
  -- In case state is no longer valid, authorization server might send this so we know where to redirect with error
  params.redirect_uri = uri_params.redirect_uri or uri_params.redirect_url
  params.access_token = uri_params.access_token 
  params.token_type = uri_params.token_type or "bearer" 
  params.expires_in = uri_params.expires_in or "604800"
  
  local header_params = ngx.req.get_headers()
  params.secret_token = header_params.X_3scale_proxy_secret_token
  
  return params
end

function check_secret(params) 
  return params.secret_token == ngx.var.secret_token
end

-- Get the token from params
function get_token(params)
  local res = {}
  local token = {}
  
  token = extract_token(params)
  res = store_token(params, token)
 
  if res.status ~= 200 then
    local error_code = res.body:match('<error code="(.*)">') 
    ngx.header.content_type = "application/x-www-form-urlencoded"
    return ngx.redirect(token.redirect_uri .. "#error=server_error&error_description="..error_code or res.body)
  else
    send_token(token)
  end
end

-- Retrieve token from params
function extract_token(params)  
  local token = {}
  
  token.access_token = params.access_token 
  token.token_type = params.token_type
  token.expires_in = params.expires_in
  token.state = params.state

  return token
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(params, token)
  local body = ts.build_query({ app_id = params.client_id, token = token.access_token, user_id = params.user_id, ttl = token.expires_in })
  local stored = ngx.location.capture( "/_threescale/oauth_store_token", 
    { method = ngx.HTTP_POST, body = body } )
  return { ["status"] = stored.status , ["body"] = stored.body }
end

-- Returns the token to the client
function send_token(token)
  ngx.header.content_type = "application/x-www-form-urlencoded"
  return ngx.redirect( token.redirect_uri .. "#access_token="..token.access_token.."&state="..token.state.."&token_type="..token.token_type.."&expires_in="..token.expires_in )
end

local params = extract_params()

local is_valid = check_secret(params)

if is_valid then
  get_token(params)
end