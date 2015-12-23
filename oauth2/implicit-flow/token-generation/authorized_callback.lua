-- authorized_callback.lua

-- Once the client has been authorized by the API provider in their
-- login, the provider is supposed to send the client (via redirect)
-- to this endpoint, with the same status code that we sent him at the
-- moment of the first redirect

local cjson = require 'cjson'
local ts = require 'threescale_utils'
local redis = require 'resty.redis'
local red = redis:new()

local function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token",
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token})

  ts.log(ts.dump(stored))
  if stored.status ~= 200 then
    ngx.say("Error. Unable to store access_token in 3scale")
    ngx.exit(ngx.HTTP_OK)
  end
end

local ok, err
local params = ngx.req.get_uri_args()

if ts.required_params_present({'state'}, params) then
  ts.connect_redis(red)
  local tmp_data = ngx.var.service_id .. "#tmp_data:".. params.state
   ok , err = red:exists(tmp_data)
  if 0 == ok then
    -- TODO: Redirect? to the initial state?
    ts.missing_args("state does not exist. Probably expired")
  end
  ok, err = red:hgetall(tmp_data)
  if not ok then
    ts.error("no values for tmp_data hash: ".. ts.dump(err))
  end

  local client_data = red:array_to_hash(ok)  -- restoring client data

   -- Delete the tmp_data:
  red:del(tmp_data)

  local access_token = client_data.access_token

  store_token(client_data.client_id, access_token)

  ngx.req.set_header("Content-Type", "application/x-www-form-urlencoded")
  return ngx.redirect(client_data.redirect_uri .. "?access_token="..access_token.."&state="..params.state.."&token_type=bearer")
else
  ts.missing_args("{ 'error': '".. "invalid_client_data from login form" .. "'}")
end
