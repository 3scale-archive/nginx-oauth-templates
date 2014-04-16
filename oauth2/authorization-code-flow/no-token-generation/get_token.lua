local cjson = require 'cjson'
local ts = require 'threescale_utils'

local function store_token(client_id, access_token, expires_in)
  
  local stored = ngx.location.capture("/_threescale/oauth_store_token", 
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. access_token..
    "&ttl="..expires_in})

  if stored.status ~= 200 then
    ngx.say("eeeerror")
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say({'{"access_token": "'.. access_token .. '", "expires_in": "'.. expires_in .. '","token_type": "bearer", "refresh_token": "'.. refresh_token ..'"}'})
  ngx.exit(ngx.HTTP_OK)
end

function get_token(params)
  local auth_code_required_params = {'client_id', 'client_secret', 'grant_type', 'code', 'redirect_uri'}
  local refresh_token_required_params =  {'client_id', 'client_secret', 'grant_type', 'refresh_token'}

  if ts.required_params_present(auth_code_required_params, params) and params['grant_type'] == 'authorization_code' then
    
    local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, body = "client_id="..params.client_id.."&client_secret="..params.client_secret.."&grant_type="..params.grant_type.."&code="..params.code.."&redirect_uri="..params.redirect_uri})
    
    if res.status ~= 200 then
      ngx.status = res.status
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.print(res.body)
      ngx.exit(ngx.HTTP_OK)
    else
      token = cjson.decode(res.body)
      access_token = token.access_token
      expires_in = token.expires_in
      refresh_token = token.refresh_token
      store_token(params.client_id, access_token, expires_in)
    end

  elseif ts.required_params_present(refresh_token_required_params, params) and params['grant_type'] == 'refresh_token' then
    
    local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, body = "client_id="..params.client_id.."&client_secret="..params.client_secret.."&grant_type="..params.grant_type.."&refresh_token="..params.refresh_token})
    
    if res.status ~= 200 then
      ngx.status = res.status
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.print(res.body)
      ngx.exit(ngx.HTTP_OK)
    else
      token = cjson.decode(res.body)
      access_token = token.access_token
      expires_in = token.expires_in
      refresh_token = token.refresh_token
      store_token(params.client_id, access_token, expires_in)
    end
  
  else
    ngx.log(0, "NOPE")
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

-- Check valid credentials first in backend
local exists = ngx.location.capture("/_threescale/redirect_uri_matches", { vars= { client_id = params.client_id, client_secret = params.client_secret, red_url = params.redirect_uri }})

if exists.status ~= 200 then
  ngx.status = 403
  ngx.header.content_type = 'text/plain; charset=us-ascii'
  ngx.print("Authentication failed")
  ngx.exit(ngx.HTTP_OK)
else
  local s = get_token(params)
end