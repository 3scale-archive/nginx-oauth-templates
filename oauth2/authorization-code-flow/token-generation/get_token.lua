local cjson = require 'cjson'
local redis = require 'resty.redis'
local ts = require 'threescale_utils'
local red = redis:new()

function generate_token(client_id)
   return ts.sha1_digest(ngx.time() .. client_id)
end

-- Returns the access token (stored in redis) for the client identified by the id
-- This needs to be called within a minute of it being stored, as it expires and is deleted
function generate_access_token_for(client_id)
   local ok, err = red:connect("127.0.0.1", 6379)
   ok, err =  red:hgetall("c:".. client_id) -- code?
   if ok[1] == nil then
      ngx.say("expired_code")
      return ngx.exit(ngx.HTTP_OK)
   else
      return red:array_to_hash(ok).pre_access_token
   end
end

local function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token",
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token})
  if stored.status ~= 200 then
    ngx.say("eeeerror")
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say({'{"access_token": "'.. token .. '", "token_type": "bearer"}'})
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

   ngx.log(0, ts.dump(params))
   if ts.required_params_present(required_params, params) and params['grant_type'] == 'authorization_code'  then
      local token = generate_access_token_for(params.client_id)
      store_token(params.client_id, token)
   else
      ngx.log(0, "NOPE")
      ngx.exit(ngx.HTTP_FORBIDDEN)
   end
end
