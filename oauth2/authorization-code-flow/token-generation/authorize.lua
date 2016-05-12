local random = require 'resty.random'
local ts = require 'threescale_utils'
local redis = require 'resty.redis'
local red = redis:new()

-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/check_credentials",
              { args=( params.client_id and "app_id="..params.client_id.."&" or "" )..
          ( params.client_secret and "app_key="..params.client_secret.."&" or "" )..
          ( ( params.redirect_uri or params.redirect_url ) and "redirect_uri="..( params.redirect_uri or params.redirect_url ) or "" ), 
          copy_all_vars = true })
  return res.status == 200
end

-- Authorizes the client for the given scope
function authorize(params)
   local required_params = {'client_id', 'redirect_uri', 'response_type', 'scope'}

   if ts.required_params_present(required_params, params) and params["response_type"] == 'code' then
      redirect_to_login(params)
   elseif params["response_type"] ~= 'code' then
      return false, 'unsupported_response_type'
   else
      return false, 'invalid_request'
   end
end

-- redirects_to the authorization url of the API provider with a secret
-- 'state' which will be used when the form redirects the user back to
-- this server.
function redirect_to_login(params)
   local n = nonce(params.client_id)

   params.scope = params.scope
   ts.connect_redis(red)
   local pre_token = generate_access_token(params.client_id)

   local ok, err = red:hmset(ngx.var.service_id .. "#tmp_data:".. n,
              {client_id = params.client_id,
               redirect_uri = params.redirect_uri,
               plan_id = params.scope,
               pre_access_token = pre_token})

   if not ok then
      ts.error(ts.dump(err))
   end

   ngx.redirect(ngx.var.auth_url .. "?scope=".. params.scope .. "&state=" .. n .. "&tok=".. pre_token)
   ngx.exit(ngx.HTTP_OK)
end

-- returns a unique string for the client_id. it will be short lived
function nonce(client_id)
   return ts.sha1_digest(tostring(random.bytes(20, true)) .. "#login:" .. client_id)
end

function generate_access_token(client_id)
   return ts.sha1_digest(tostring(random.bytes(20, true)) .. client_id)
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
  local ok, err = authorize(params)

  if not ok then
    ngx.redirect(ngx.var.auth_url .. "?scope=" .. params.scope .. "&state=" .. (params.state or '') .. "&error=".. err)
  end
else
  ngx.redirect(ngx.var.auth_url .. "?scope=" .. params.scope .. "&state=" .. (params.state or '') .. "&error=invalid_client")
end