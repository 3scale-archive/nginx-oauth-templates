local cjson = require 'cjson'
local ts = require 'threescale_utils'
local redis = require 'resty.redis'
local red = redis:new()

-- As per RFC for Authorization Code flow: extract params from Authorization header and body
-- If implementation deviates from RFC, this function should be over-ridden
function extract_params()
  local params = {}
  local header_params = ngx.req.get_headers()

  if header_params['Authorization'] then
    params.authorization = ngx.decode_base64(header_params['Authorization']:split(" ")[2])
    params.client_id = params.authorization:split(":")[1]
    params.client_secret = params.authorization:split(":")[2]
  end

  ngx.req.read_body()
  local body_params = ngx.req.get_post_args()

  params.grant_type = body_params.grant_type or nil
  params.code = body_params.code or nil 
  params.redirect_uri = body_params.redirect_uri or nil 

  return params
end

-- Check valid credentials
function check_credentials(params)
  local res = check_client_credentials(params)
  return res.status == 200
end


-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/check_credentials",
              { args = { app_id = params.client_id or nil, app_key = params.client_secret or nil, redirect_uri = params.redirect_uri or params.redirect_url or nil },
                copy_all_vars = true })

  if res.status ~= 200 then   
    ngx.status = 401
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print('{"error":"invalid_client"}')
    ngx.exit(ngx.HTTP_OK)
  end

  return { ["status"] = res.status, ["body"] = res.body }
end

-- Get the token from Redis
function get_token(params)
  local required_params = {'client_id', 'client_secret', 'grant_type', 'code', 'redirect_uri'}

  local res = {}
  local token = {}

  if ts.required_params_present(required_params, params) and params['grant_type'] == 'authorization_code'  then
    res = request_token(params)
  else
    res = { ["status"] = 403, ["body"] = '{"error": "invalid_request"}' }
  end

  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    token = res.body
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

-- Returns the access token (stored in redis) for the client identified by the id
-- This needs to be called within a minute of it being stored, as it expires and is deleted
function request_token(params)
  local ok, err = red:connect("127.0.0.1", 6379)
  ok, err =  red:hgetall("c:".. params.code)
  
  if ok[1] == nil then
    return { ["status"] = 403, ["body"] = '{"error": "expired_code"}' }
  else
    local client_data = red:array_to_hash(ok)
    if params.code == client_data.code then
      return { ["status"] = 200, ["body"] = { ["access_token"] = token, ["token_type"] = "bearer", ["expires_in"] = 604800 } }
    else
      return { ["status"] = 403, ["body"] = '{"error": "invalid authorization code"}' }
    end
  end
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(params, token)
  local body = ts.build_query({ app_id = token.client_id, token = token.access_token, user_id = params.username or nil, ttl = token.expires_in })
  local stored = ngx.location.capture( "/_threescale/oauth_store_token", 
    { method = ngx.HTTP_POST, body = body } )
  return { ["status"] = stored.status , ["body"] = stored.body }
end

-- Returns the token to the client
function send_token(token)
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(cjson.encode(token))
  ngx.exit(ngx.HTTP_OK)
end

local params = extract_params()

local exists = check_credentials(params)

if exists then
  get_token(params)
end