local cjson = require 'cjson'
local ts = require 'threescale_utils'

function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/client_secret_matches",
          { args="app_id="..params.client_id.."&app_key="..params.client_secret, share_all_vars = true })
  local secret = res.body:match("<key>([^<]+)</key>")
  return (params.secret == secret)
end

local function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token", 
    {method = ngx.HTTP_POST, 
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token.access_token ..
    "&ttl="..token.expires_in or "-1"})

  if stored.status ~= 200 then
    ngx.say('{"error":"invalid_request"}')
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(cjson.encode(token))
  ngx.exit(ngx.HTTP_OK)
end

function get_token(params)
  local access_token_required_params = {'client_id', 'client_secret', 'grant_type'}
  local refresh_token_required_params =  {'client_id', 'client_secret', 'grant_type', 'refresh_token'}
  local res = {}

  if ts.required_params_present(access_token_required_params, params) and params['grant_type'] == 'client_credentials' then
    res = ngx.location.capture("/_oauth/token", 
      { method = ngx.HTTP_POST, 
      body = "client_id="..params.client_id..
      "&client_secret="..params.client_secret..
      "&grant_type="..params.grant_type} )
  elseif ts.required_params_present(refresh_token_required_params, params) and params['grant_type'] == 'refresh_token' then
    res = ngx.location.capture("/_oauth/token", 
      { method = ngx.HTTP_POST, 
      body = "client_id="..params.client_id..
      "&client_secret="..params.client_secret..
      "&grant_type="..params.grant_type..
      "&refresh_token="..params.refresh_token})
  else
    res = { ["status"] = "403", ["body"] = "invalid_request" }
  end

  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print('{"error":"' .. res.body .. '"}')
    ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    token = cjson.decode(res.body)
    store_token(params.client_id, token)
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

if exists then
  get_token(params)
else
  ngx.status = 401
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.print('{"error":"invalid_client"}')
  ngx.exit(ngx.HTTP_OK)
end