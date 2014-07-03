# OAuth 2

## API Calls

### To store an access_token

`curl -X POST "http://su1.3scale.net/services/<SERVICE_ID>/oauth_access_tokens.xml?provider_key=<PROVIDER_KEY>&app_id=<CLIENT_ID>&token=<TOKEN>&ttl=<TTL>"`

 returns nothing

Params:

- provider_key
- app_id
- token
- ttl (optional) -  
 Seconds to expiry. If no ttl is set, it will be a non-expiring token, otherwise it gets automatically deleted once the time is up  

### To delete an access_token

`curl -X DELETE "http://su1.3scale.net/services/<SERVICE_ID>/oauth_access_tokens/<TOKEN>.xml?provider_key=<PROVIDER_KEY>"`

 returns nothing

### To retrieve the access tokens issued to an application

`curl -X GET "http://su1.3scale.net/services/<SERVICE_ID>/applications/<CLIENT_ID>/oauth_access_tokens.xml?provider_key=<PROVIDER_KEY>"`

 returns

```xml
<?xml version="1.0" encoding="UTF-8"?>
<oauth_access_tokens>
  <oauth_access_token ttl="-1">96c85326-6171-4058-a0e3-261cf73b3b87</oauth_access_token>
  <oauth_access_token ttl="-1">7890f1a8-7df4-4d02-84e4-0c4032cd7074</oauth_access_token>
  <oauth_access_token ttl="-1">78d61fdb-3d02-4fb8-8b92-3d9bdbc2e5fa</oauth_access_token>
</oauth_access_tokens>
```

### To get the application a token belongs to

`curl -X GET "http://su1.3scale.net/services/<SERVICE_ID>/oauth_access_tokens/<TOKEN>.xml?provider_key=<PROVIDER_KEY>"`

 returns 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<application>
  <app_id>resourceowner</app_id>
</application>
```


## client-credentials-flow

## resource-owner-password-flow

## implicit-flow

## authorization-code-flow

## utils

Contains threescale_utils.lua file which is used with all flows.
