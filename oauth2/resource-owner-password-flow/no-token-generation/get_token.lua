local ts = require 'threescale_utils'

local function store_token(client_id, body)
  -- Extract token from response - assuming it's in json format
  value = cjson.decode(body)
  token = value.access_token
  local stored = ngx.location.capture("/_threescale/oauth_store_token",
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token})
  if stored.status ~= 200 then
    ngx.say("error")
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(body)
  ngx.exit(ngx.HTTP_OK)
end

function get_token(params)
  local required_params = {'username', 'password', 'grant_type', CHANGE_ME_ADDITIONAL_PARAMS}
  local args

  if ts.required_params_present(required_params, params) and params['grant_type'] == 'password' then
    args = "username="..params.username.."&password="..params.password.."&grant_type=password"
  else
    ngx.log(0, "NOPE")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local res = ngx.location.capture("/_oauth/token", { method = ngx.CHANGE_ME_HTTP_METHOD, args = args } ) 
  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_OK)
  else
    store_token(params.client_id, res.body)
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