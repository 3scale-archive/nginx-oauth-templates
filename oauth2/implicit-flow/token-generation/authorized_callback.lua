-- authorized_callback.lua

-- Once the client has been authorized by the API provider in their
-- login, the provider is supposed to send the client (via redirect)
-- to this endpoint, with the same status code that we sent him at the
-- moment of the first redirect
local ts = require 'threescale_utils'
local redis = require 'resty.redis'
local red = redis:new()

-- The authorization server should send some data in the callback response to let the
-- API Gateway know which user to associate with the token. 
-- We assume that this data will be sent as uri params. 
-- This function should be over-ridden depending on authorization server implementation.
function extract_params()
  local params = {}
  local uri_params = ngx.req.get_uri_args()
  
  if uri_params.username then
    params.username = uri_params.username
  end

  if uri_params.state then
    params.state = uri_params.state
  end
  
  -- In case state is no longer valid, authorization server might send this so we know where to redirect with error
  if uri_params.redirect_uri then
    params.redirect_uri = uri_params.redirect_uri
  end
  
  return params
end

-- Check valid state parameter sent
function check_state(params)
  local required_params = {'state'}

  local valid_state = false
  if ts.required_params_present(required_params, params) then  
    local tmp_data = ngx.var.service_id .. "#tmp_data:".. params.state
    local ok = red:exists(tmp_data)

    if ok == 0 then
      ngx.header.content_type = "application/x-www-form-urlencoded"
      return ngx.redirect(params.redirect_uri .. "#error=invalid_request&error_description=invalid_or_expired_state&state="..params.state)
    end

    valid_state = true
  else
    ngx.header.content_type = "application/x-www-form-urlencoded"
    return ngx.redirect(params.redirect_uri .. "#error=invalid_request&error_description=missing_state")
  end

  return valid_state
end

-- Get the token from Redis
function get_token(params)
  local res = {}
  local token = {}
  
  token = retrieve_token(params)
  res = store_token(params, token)
 
  if res.status ~= 200 then
    ngx.header.content_type = "application/x-www-form-urlencoded"
    return ngx.redirect(token.redirect_uri .. "#error=server_error&error_description="..res.body)
  else
    send_token(token)
  end
end

-- Retrieve client data from Redis
function retrieve_token(params)
  local tmp_data = ngx.var.service_id .. "#tmp_data:".. params.state
  
  ts.connect_redis(red)  
  local ok, err = red:hgetall(tmp_data)
  
  if not ok then
    ngx.log(0, "no values for tmp_data hash: ".. ts.dump(err))
    ngx.header.content_type = "application/x-www-form-urlencoded"
    return ngx.redirect(params.redirect_uri .. "#error=invalid_request&error_description=invalid_or_expired_state")
  end

  -- Restore client data into token hash
  local token = red:array_to_hash(ok)
  -- Delete tmp_data:
  red:del(tmp_data)
  
  token.expires_in = 604800
  token.state = params.state

  return token
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(params, token)
  local stored = ngx.location.capture( "/_threescale/oauth_store_token", 
    { method = ngx.HTTP_POST, body = { provider_key = ngx.var.provider_key, app_id = token.client_id, token = token.access_token, user_id = params.username or nil , ttl = token.expires_in } } )
  return { ["status"] = stored.status , ["body"] = stored.body }
end

-- Returns the token to the client
function send_token(token)
  ngx.header.content_type = "application/x-www-form-urlencoded"
  return ngx.redirect( token.redirect_uri .. "#access_token="..token.access_token.."&state="..token.state.."&token_type=bearer&expires_in="..token.expires_in )
end

local params = extract_params()

local exists = check_state(params)

if exists then
  get_token(params)
end