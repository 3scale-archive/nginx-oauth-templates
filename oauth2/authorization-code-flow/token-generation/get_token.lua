local redis = require 'resty.redis'
local red = redis:new()
local ts = require 'threescale_utils'


function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/check_credentials",
				  { args=params, share_all_vars = true })
  return res
end

-- Returns the access token (stored in redis) for the client identified by the id
-- This needs to be called within a minute of it being stored, as it expires and is deleted
function generate_token(params)
  local ok, err = red:connect("127.0.0.1", 6379)
  ok, err =  red:hgetall("c:".. params.code)
  
  if ok[1] == nil then
    ngx.say("expired_code")
    return ngx.exit(ngx.HTTP_OK)
  else
    local client_data = red:array_to_hash(ok)
    if params.code == client_data.code and check_client_credentials(params) then
      return client_data.pre_access_token
    else
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.say({'{"error": "invalid authorization code"}'})
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end
end

local function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token",
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token..
    "&ttl=604800"})
  
  if stored.status ~= 200 then
    ngx.say('{"error":"invalid_request"}')
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say('{"access_token": "'.. token .. '", "token_type": "bearer", "expires_in":604800}')
  ngx.exit(ngx.HTTP_OK)
end

function get_token(params)
  local required_params = {'client_id', 'redirect_uri', 'client_secret', 'code', 'grant_type'}

  if ts.required_params_present(required_params, params) and params['grant_type'] == 'authorization_code'  then
    local token = generate_token(params)
    store_token(params.client_id, token)
  else
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print('{"error":"invalid_request"}')
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

local params = {}

if "GET" == ngx.req.get_method() then
  params = ngx.req.get_uri_args()
else
  ngx.req.read_body()
  params = ngx.req.get_post_args()
end

-- Check valid client_id / secret first in back end
local exists = check_client_credentials(params)

if exists.status ~=200 then
  get_token(params)
else
  ngx.status = 401
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.print('{"error":"invalid_client"}')
  ngx.exit(ngx.HTTP_OK)
end