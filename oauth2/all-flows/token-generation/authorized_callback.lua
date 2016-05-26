-- authorized_callback.lua

-- Once the client has been authorized by the API provider in their
-- login, the provider is supposed to send the client (via redirect)
-- to this endpoint, with the same status code that we sent him at the
-- moment of the first redirect

local cjson = require 'cjson'
local ts = require 'threescale_utils'
local redis = require 'resty.redis'
local red = redis:new()

local ok, err
local params = ngx.req.get_uri_args()

if ts.required_params_present({'state', 'response_type'}, params) then
   ts.connect_redis(red)
   local tmp_data = ngx.var.service_id .. "#state:".. params.state
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
   local response
   -- Delete the tmp_data:
   red:del(tmp_data)

  if params.response_type == 'code' then
    local code = ts.sha1_digest(math.random() .. "#code:" .. client_data.client_id)
     ok, err =  red:hmset("c:".. client_data.client_id, {client_id = client_data.client_id,
						       client_secret = client_data.secret_id,
						       redirect_uri = client_data.redirect_uri,
						       access_token = client_data.access_token,
						       code = code,
                               user_id = params.user_id })

     ok, err =  red:expire("c:".. client_data.client_id, 60 * 10) -- code expires in 10 mins

     response = "?code="..code .. "&state=" .. (params.state or "")
    if not ok then
      ngx.say("failed to hmset: ", err)
      ngx.exit(ngx.HTTP_OK)
    end
  elseif params.response_type == 'token' then
     local access_token = client_data.access_token
     -- call endpoint to store token
     local stored = ngx.location.capture("/_oauth/token", {method = ngx.HTTP_POST, body = "provider_key=" ..ngx.var.provider_key ..
                                         "&app_id=".. client_data.client_id ..
                                         "&token=".. access_token..
                                         (params.username and "&username="..params.username or "")})
     
      if stored.status ~= 200 then
        ngx.say("Error. Unable to store access_token in 3scale")
        ngx.exit(ngx.HTTP_OK)
      end
    response = "?access_token="..access_token
  end

  ngx.req.set_header("Content-Type", "application/x-www-form-urlencoded")
  return ngx.redirect(client_data.redirect_uri .. response)
else
  ts.missing_args("{ 'error': '".. "invalid_client_data from login form" .. "'}")
end
