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

-- Check valid credentials
function check_credentials(params)
  local res = check_client_credentials(params)
  return res.status == 200
end

-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
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
  local access_token_required_params = {'username', 'password', 'grant_type'}
  local refresh_token_required_params =  {'client_id', 'client_secret', 'grant_type', 'refresh_token'}
  
  local res = {}
  
  if (ts.required_params_present(access_token_required_params, params) and params['grant_type'] == 'password') or 
    (ts.required_params_present(refresh_token_required_params, params) and params['grant_type'] == 'refresh_token') then
    res = request_token(params)
  else
    res = { ["status"] = 403, ["body"] = '{"error": "invalid_request"}' }
  end

  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    local token = parse_token(res.body)
    local stored = store_token(params.client_id, token)

    if stored.status ~= 200 then
      ngx.say(stored.body)
      ngx.status = stored.status
      ngx.exit(ngx.HTTP_OK)
    else
      send_token(token)
    end
  end
end

-- Calls the token endpoint to request a token
function request_token()
  local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, copy_all_vars = true })
  return { ["status"] = res.status, ["body"] = res.body }
end

-- Parses the token - in this case we assume a json encoded token. This function may be overwritten to parse different token formats.
function parse_token(body)
  local token = cjson.decode(body)
  return token
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(params, token)
  local stored = ngx.location.capture("/_threescale/oauth_store_token", 
    {method = ngx.HTTP_POST,
    body = "provider_key=" ..ngx.var.provider_key ..
    "&app_id=".. params.client_id ..
    "&token=".. token.access_token ..
    "&user_id=".. params.username ..
    "&ttl="..(token.expires_in or "604800")})
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