local ts = require 'threescale_utils'
local redis = require 'resty.redis'
local red = redis:new()

-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/check_credentials",
				  { args=params, share_all_vars = true })
  return res.status == 200
end

-- Get the token from Redis
function get_token(params)
  local required_params = {'client_id', 'client_secret', 'grant_type', 'code', 'redirect_uri'}

  local res = {}

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
    local token = res.body
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
      return { ["status"] = 200, ["body"] = client_data.pre_access_token }
    else
      return { ["status"] = 403, ["body"] = '{"error": "invalid authorization code"}' }
    end
  end
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token",
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token..
    "&ttl=604800")})
  return stored
end

-- Returns the token to the client
function send_token(token)
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say('{"access_token": "'.. token .. '", "token_type": "bearer", "expires_in":604800 }')
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
