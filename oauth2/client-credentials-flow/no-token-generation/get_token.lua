local ts = require 'threescale_utils'

local function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token", {method = ngx.HTTP_POST, body = "provider_key=" ..ngx.var.provider_key .."&app_id=".. client_id .."&token=".. token})
  if stored.status ~= 200 then
    ngx.say("eeeerror")
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say({'{"access_token": "'.. token .. '", "token_type": "bearer"}'})
  ngx.exit(ngx.HTTP_OK)
end

function get_token(params)
  local required_params = {'client_id', 'client_secret', 'grant_type'}

  if ts.required_params_present(required_params, params) and params['grant_type'] == 'client_credentials' then
    local res = ngx.location.capture("/_oauth/token", { method = ngx.CHANGE_ME_HTTP_METHOD, args = "client_id="..params.client_id.."&client_secret="..params.client_secret.."&grant_type="..params.grant_type} )
    if res.status ~= 200 then
      ngx.status = res.status
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.print(res.body)
      ngx.exit(ngx.HTTP_OK)
    else
      -- Extract token from response - assuming it's in json format
      value = cjson.decode(res.body)
      token = value.access_token
      store_token(params.client_id, token)
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

-- Check valid client_id / secret first in back end
local exists = ngx.location.capture("/_threescale/auth", { args="app_id="..params.client_id.."&app_key="..params.client_secret, share_all_vars = true })

if exists.status ~= 200 then
  ngx.status = 403
  ngx.header.content_type = 'text/plain; charset=us-ascii'
  ngx.print("Authentication failed")
  ngx.exit(ngx.HTTP_OK)
else
  local s = get_token(params)
end