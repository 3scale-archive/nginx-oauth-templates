local ts = require 'threescale_utils'

function check_client_secret(params)
  local res = ngx.location.capture("/_threescale/client_secret_matches",
          { args="app_id="..params.client_id.."&app_key="..params.client_secret, share_all_vars = true })
  local secret = res.body:match("<key>([^<]+)</key>")
  return (params.secret == secret)
end

function generate_token(params)
 return ts.sha1_digest(ngx.time() .. params.client_id)
end

local function store_token(client_id, access_token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token",
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. access_token..
    "&ttl=604800"})
  if stored.status ~= 200 then
    ngx.say('{"error":"'..stored.body'"}')
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say({'{"access_token": "'.. token .. '", "token_type": "bearer", "expires_in":604800}'})
  ngx.exit(ngx.HTTP_OK)
end

function get_token(params)
  local required_params = {'client_id', 'client_secret', 'grant_type'}

  if ts.required_params_present(required_params, params) and params['grant_type'] == 'client_credentials' then
    local token = generate_token(params)
    store_token(params.client_id, token)
  else
    ngx.log(0, "Missing required params or incorrect grant_type")
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
local exists = check_client_secret(params)

if exists then
  get_token(params)
else
  ngx.status = 403
  ngx.header.content_type = 'text/plain; charset=us-ascii'
  ngx.print("Authentication failed")
  ngx.exit(ngx.HTTP_OK)
end