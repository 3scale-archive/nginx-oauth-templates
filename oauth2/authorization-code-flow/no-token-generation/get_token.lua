local cjson = require 'cjson'
local ts = require 'threescale_utils'

-- Check valid params client_id / secret / redirect_url (whichever are sent) against 3scale
function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/check_credentials",
              { args=params, share_all_vars = true })
  return res.status == 200
end

-- Get the token from the OAuth Server
function get_token(params)
  local access_token_required_params = {'client_id', 'client_secret', 'grant_type', 'code', 'redirect_uri'}
  local refresh_token_required_params =  {'client_id', 'client_secret', 'grant_type', 'refresh_token'}

  local res = {}

  if (ts.required_params_present(access_token_required_params, params) and params['grant_type'] == 'authorization_code') or 
    (ts.required_params_present(refresh_token_required_params, params) and params['grant_type'] == 'refresh_token') then  
    res = request_token(params)
  else
    res = { ["status"] = 403, ["body"] = '{"error": "invalid_request"}'  }
  end

  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    local token = parse_token(res.body)
    local stored = store_token(params.client_id, token)
    
    if stored.status ~= 200 then
      ngx.say('{"error":"'..stored.body..'"}')
      ngx.status = stored.status
      ngx.exit(ngx.HTTP_OK)
    else
      send_token(token)
    end
  end
end

-- Calls the token endpoint to request a token
function request_token(params)
  local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, copy_all_vars = true })
  return { ["status"] = res.status, ["body"] = res.body }
end

-- Parses the token - in this case we assume a json encoded token. This function may be overwritten to parse different token formats.
function parse_token(body)
  local token = cjson.decode(res.body)
  return token
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token", 
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token.access_token..
    "&ttl="..(token.expires_in or "604800")})
  return stored
end

-- Returns the token to the client
function send_token(token)
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(cjson.encode(token))
  ngx.exit(ngx.HTTP_OK)
end

local params = {}

if "GET" == ngx.req.get_method() then
  params = ngx.req.get_uri_args()
else
  ngx.req.read_body()
  params = ngx.req.get_post_args()
end

local exists = check_client_credentials(params)

if exists then
  get_token(params)
else
  ngx.status = 401
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.print('{"error":"invalid_client"}')
  ngx.exit(ngx.HTTP_OK)
end