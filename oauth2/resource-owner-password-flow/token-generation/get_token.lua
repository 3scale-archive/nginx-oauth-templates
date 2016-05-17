local cjson = require 'cjson'
local ts = require 'threescale_utils'

-- As per RFC for Resource Owner Password flow: extract params from Authorization header and body
-- If implementation deviates from RFC, this function should be over-ridden
function extract_params()
  local params = {}
  local header_params = ngx.req.get_headers()

  if header_params['Authorization'] then
    params.authorization = ngx.decode_base64(header_params['Authorization']:split(" ")[2])
    params.client_id = params.authorization:split(":")[1]
    params.client_secret = params.authorization:split(":")[2]
  end

  ngx.req.read_body()
  local body_params = ngx.req.get_post_args()
  
  params.grant_type = body_params.grant_type
  params.username = body_params.username
  params.password = body_params.password

  if params.grant_type == "refresh_token" then
    params.refresh_token = body_params.refresh_token
  end

  return params
end

-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
function check_credentials(params)
  local res_user = check_user_credentials(params)
  local res_client = check_client_credentials(params)

  return res_client.status == 200 and res_user.status == 200
end

-- Calls the login endpoint to verify user credentials
function check_user_credentials(params)
  local body = '{"type": "basic", "value": "'..ngx.encode_base64(params.username..':'..params.password)..'" }'
  local res = ngx.location.capture("/_login", { method = ngx.HTTP_POST,  body = body})

  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  return { ["status"] = res.status, ["body"] = res.body }
end


function check_client_credentials(params)
   local res = ngx.location.capture("/_threescale/check_credentials",
              { args=( params.client_id and "app_id="..params.client_id.."&" or "" )..
                     ( params.client_secret and "app_key="..params.client_secret.."&" or "" )..
                     ( params.redirect_uri and "redirect_uri="..params.redirect_uri or "" )})

  if res.status ~= 200 then   
    ngx.status = 401
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print('{"error":"invalid_client"}')
    ngx.exit(ngx.HTTP_OK)
  end

  return { ["status"] = res.status, ["body"] = res.body }
end

-- Get the token from the OAuth Server
function get_token(params)
  local required_params = {'username', 'password', 'grant_type'}
  local res = {}

  if ts.required_params_present(access_token_required_params, params) and params['grant_type'] == 'password' then
    local token = generate_token(params)
    res = store_token(params.client_id, token)
  else
    res = { ["status"] = 403, ["body"] = '{"error": "invalid_request"}'  }
  end

  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    send_token(token)
  end
end

function generate_token(client_id)
  local token = ts.sha1_digest(tostring(random.bytes(20, true)) .. client_id)
  return { ["access_token"] = token, ["token_type"] = "bearer", ["expires_in"] = 604800 }
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(client_id, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token", 
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. client_id ..
    "&token=".. token.access_token..
    "&ttl=".. token.expires_in })
  return { ["status"] = stored.status , ["body"] = stored.body }
end

-- Returns the token to the client
function send_token(token)
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(cjson.encode(token))
  ngx.exit(ngx.HTTP_OK)
end

local params = extract_params()

local exists = check_credentials(params)

if exists then
  get_token(params)
end