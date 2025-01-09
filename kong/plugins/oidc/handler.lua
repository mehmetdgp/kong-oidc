local OidcHandler = {
    VERSION = "1.3.2",
    PRIORITY = 1000,
}
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local openidc = require("kong.plugins.oidc.openidc")

function OidcHandler:access(config)
  local oidcConfig = utils.get_options(config, ngx)
 
     -- "mzkhead" adlı cookie'yi oku
     local mzkhead_value = get_cookie_value("mzk_twort")

     -- Eğer cookie değeri bulunursa header olarak ekle
     if mzkhead_value then
         ngx.req.set_header("Mzk-New", mzkhead_value)
         kong.log.info("Mzk-New header set with value: " .. mzkhead_value)
     else
         kong.log.info("mzkhead cookie not found. Mzk-New header not set.")
     end

  local function stringify(obj)
    if type(obj) == "table" then
      local s = "{ "
      for k, v in pairs(obj) do
        if type(k) ~= "number" then k = '"' .. k .. '"' end
        s = s .. "[" .. k .. "] = " .. stringify(v) .. ","
      end
      return s .. "} "
    else
      return tostring(obj)
    end
  end

  kong.log.info("mzk-oidc-config: " .. stringify(oidcConfig))
  local service = kong.router.get_service()

    if service then
        kong.log.info("Service ID mzk-second 11: " .. service.id)
        kong.log.info("Service Name: " .. service.name)
        -- Diğer service özelliklerine erişim sağlanabilir
    else
        kong.log.info("Request did not match any service.")
    end

  local route = kong.router.get_route()

    if route then
        kong.log.info("Route ID: " .. route.id)
        kong.log.info("Route Name: " .. route.name)
    else
        kong.log.info("Request did not match any route.")
    end
  
   if filter.shouldProcessRequestRegex(oidcConfig) then
    ngx.log(ngx.DEBUG, "ignore_request_regex detected service: " .. kong.request.get_path())
    return
  end


  -- partial support for plugin chaining: allow skipping requests, where higher priority
  -- plugin has already set the credentials. The 'config.anomyous' approach to define
  -- "and/or" relationship between auth plugins is not utilized
  if oidcConfig.skip_already_auth_requests and kong.client.get_credential() then
    ngx.log(ngx.DEBUG, "OidcHandler ignoring already auth request: " .. ngx.var.request_uri)
    return
  end

  if filter.shouldProcessServices(oidcConfig) then
    ngx.log(ngx.DEBUG, "OidcHandler ignoring service: " .. service.name)
    return
  end

  if filter.shouldProcessRoutes(oidcConfig) then
    ngx.log(ngx.DEBUG, "OidcHandler ignoring route: " .. route.name)
    return
  end

  if filter.shouldProcessRequestMethod(oidcConfig) then
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request method: ".. ngx.var.request_method)
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request path: " .. ngx.var.request_uri)
    return
  end

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  local err
  kong.log.info('mzk handle one')

  if oidcConfig.bearer_jwt_auth_enable then
    response,err,has_token_header = verify_bearer_jwt(oidcConfig)
    kong.log.info('mzk handle two' .. tostring(has_token_header))

    if oidcConfig.disable_jwt_validation and has_token_header then
      ngx.log(ngx.DEBUG, "disable validation : true")
      return
    end

    if response then
      utils.setCredentials(response)
      utils.injectGroups(response, oidcConfig.groups_claim)
      utils.injectHeaders(oidcConfig.header_names, oidcConfig.header_claims, { response })
      if not oidcConfig.disable_userinfo_header then
        utils.injectUser(response, oidcConfig.userinfo_header_name)
      end
      return
    end

    if err then
      if err == 'unauthorized request' then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        return kong.response.error(ngx.HTTP_UNAUTHORIZED)
      end

      if err == 'not_found' then
        return kong.response.error(ngx.HTTP_NOT_FOUND)
      end
    end
    
  end

  if oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)
    if response then
      utils.setCredentials(response)
      utils.injectGroups(response, oidcConfig.groups_claim)
      utils.injectHeaders(oidcConfig.header_names, oidcConfig.header_claims, { response })
      if not oidcConfig.disable_userinfo_header then
        utils.injectUser(response, oidcConfig.userinfo_header_name)
      end
    end
  end

  if response == nil then
    response = make_oidc(oidcConfig)
    if response then
      if response.user or response.id_token then
        -- is there any scenario where lua-resty-openidc would not provide id_token?
        utils.setCredentials(response.user or response.id_token)
      end
      if response.user and response.user[oidcConfig.groups_claim]  ~= nil then
        utils.injectGroups(response.user, oidcConfig.groups_claim)
      elseif response.id_token then
        utils.injectGroups(response.id_token, oidcConfig.groups_claim)
      end
      utils.injectHeaders(oidcConfig.header_names, oidcConfig.header_claims, { response.user, response.id_token })
      if (not oidcConfig.disable_userinfo_header
          and response.user) then
        utils.injectUser(response.user, oidcConfig.userinfo_header_name)
      end
      if (not oidcConfig.disable_access_token_header
          and response.access_token) then
        utils.injectAccessToken(response.access_token, oidcConfig.access_token_header_name, oidcConfig.access_token_as_bearer)
      end
      if (not oidcConfig.disable_id_token_header
          and response.id_token) then
        utils.injectIDToken(response.id_token, oidcConfig.id_token_header_name)
      end
    end
  end
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested method: " .. ngx.var.request_method)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local session_opts = utils.getSessionOptions(oidcConfig)
  local unauth_action = oidcConfig.unauth_action
  if unauth_action ~= "auth" then
    -- constant for resty.oidc library
    unauth_action = "deny"
  end
  local res, err = openidc.authenticate(oidcConfig, ngx.var.request_uri, unauth_action,session_opts)

  if err then
    if err == 'unauthorized request' then
      return kong.response.error(ngx.HTTP_UNAUTHORIZED)
    else
      if oidcConfig.recovery_page_path then
    	  ngx.log(ngx.DEBUG, "Redirecting to recovery page: " .. oidcConfig.recovery_page_path)
        ngx.redirect(oidcConfig.recovery_page_path)
      end
      return kong.response.error(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() and oidcConfig.bearer_only == "yes" then
    local res, err
    if oidcConfig.use_jwks == "yes" then
      res, err = openidc.bearer_jwt_verify(oidcConfig)
    else
      res, err = openidc.introspect(oidcConfig)
    end
    if err then
      if oidcConfig.bearer_only == "yes" then
        kong.log.err('Bearer JWT verify failed: ' .. err)
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        return kong.response.error(ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    if oidcConfig.validate_scope == "yes" then
      local validScope = false
      if res.scope then
        for scope in res.scope:gmatch("([^ ]+)") do
          if scope == oidcConfig.scope then
            validScope = true
            break
          end
        end
      end
      if not validScope then
        kong.log.err("Scope validation failed")
        return kong.response.error(ngx.HTTP_FORBIDDEN)
      end
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

function verify_bearer_jwt(oidcConfig)
  if not utils.has_bearer_access_token() then
    return nil,nil,false
  end

  if oidcConfig.disable_jwt_validation then
    ngx.log(ngx.DEBUG, "disable validation : true")
    return nil,nil,true
  end
  -- setup controlled configuration for bearer_jwt_verify
  local opts = {
    accept_none_alg = false,
    accept_unsupported_alg = false,
    token_signing_alg_values_expected = oidcConfig.bearer_jwt_auth_signing_algs,
    discovery = oidcConfig.discovery,
    timeout = oidcConfig.timeout,
    ssl_verify = oidcConfig.ssl_verify
  }

  local issuer = oidcConfig.issuer
 
  if utils.isNullOrWhitespace(issuer) then
  local discovery_doc, err = openidc.get_discovery_doc(opts)
    if err then
      kong.log.err('Discovery document retrieval for Bearer JWT verify failed')
      return nil,'not_found',true
    end
    issuer = discovery_doc.issuer
  end 
  local allowed_auds = oidcConfig.bearer_jwt_auth_allowed_auds --or oidcConfig.client_id

  local jwt_validators = require "resty.jwt-validators"
  jwt_validators.set_system_leeway(120)
  local claim_spec = {
    -- mandatory for id token: iss, sub, aud, exp, iat
    iss = jwt_validators.equals(issuer),
    azp = jwt_validators.equals(oidcConfig.client_id),
    sub = jwt_validators.required(),
    aud = function(val) return utils.has_common_item(val, allowed_auds) end,
    exp = jwt_validators.is_not_expired(),
    iat = jwt_validators.required(),
    -- optional validations
    nbf = jwt_validators.opt_is_not_before(),
  }

  local json, err, token = openidc.bearer_jwt_verify(opts, claim_spec)
  if err then
    kong.log.err('Bearer JWT verify failed: ' .. err)
    return nil,'unauthorized request',true
  end

  return json,nil,true
end

local function get_cookie_value(key)
  local cookies = ngx.var.http_cookie
  if cookies then
      for cookie in cookies:gmatch("([^;]+)") do
          local k, v = cookie:match("%s*(.-)%s*=%s*(.+)%s*")
          if k == key then
              return v
          end
      end
  end
  return nil
end

return OidcHandler
