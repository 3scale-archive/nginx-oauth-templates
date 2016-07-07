#!/usr/bin/env bash

export PATH=/usr/local/openresty/nginx/sbin:$PATH
export PROVIDER_KEY=provider_key
export USER_KEY=user_key
export CLIENT_ID=client_id
export CLIENT_SECRET=client_secret
export SERVICE_ID=service_id
export API_BACKEND=api_backend
export PORT=port

exec prove "$@"