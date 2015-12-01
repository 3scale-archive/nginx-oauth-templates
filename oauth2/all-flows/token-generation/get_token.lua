local cjson = require 'cjson'
local redis = require 'resty.redis'
local ts = require 'threescale_utils'
local red = redis:new()


function check_client_secret(client_id, secret)
  local res = ngx.location.capture("/_threescale/client_secret_matches",
				  { vars = { client_id = client_id }})
  local real_secret = res.body:match("<key>([^<]+)</key>")
  return (secret == real_secret)
end

function generate_token(client_id)
   return ts.sha1_digest(ngx.time() .. client_id)
end

-- Returns the access token (stored in redis) for the client identified by the id
-- This needs to be called within a minute of it being stored, as it expires and is deleted
function generate_access_token_for(params)
  local ok, err = red:connect("127.0.0.1", 6379)
  ok, err =  red:hgetall("c:".. params.client_id)
  
  if ok[1] == nil then
    ngx.say("expired_code")
    return ngx.exit(ngx.HTTP_OK)
  else
    local client_data = red:array_to_hash(ok)
    if params.code == client_data.code and check_client_secret(params.client_id, params.client_secret) then
      return client_data.pre_access_token..":"..client_data.user_id
    else
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.say({'{"error": "invalid authorization code"}'})
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end
end

local function store_token(params)
  local stored = ngx.location.capture("/_threescale/oauth_store_token",
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. params.client_id ..
    "&token=".. params.token..":"..params.username
    "&ttl=".. (params.ttl or "-1")})
  if stored.status ~= 200 then
    ngx.say("eeeerror")
    ngx.exit(ngx.HTTP_OK)
  end

 access_token = token:split(":")[1]

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say({'{"access_token": "'.. access_token .. '", "token_type": "bearer"}'})
  ngx.exit(ngx.HTTP_OK)
end

function get_token()
  local params = {}
  if "GET" == ngx.req.get_method() then
    params = ngx.req.get_uri_args()
  else
    ngx.req.read_body()
    params = ngx.req.get_post_args()
  end

  local required_params = {'client_id', 'redirect_uri', 'client_secret', 'code', 'grant_type'}

  if ts.required_params_present(required_params, params) and params['grant_type'] == 'authorization_code'  then
    local token = generate_access_token_for(params)
    store_token(params.client_id, token)
  else
    ngx.log(0, "NOPE")
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

local params = ngx.req.get_uri_args()

if params.token then
  local s = store_token(params)
else
  local s = get_token()
end

