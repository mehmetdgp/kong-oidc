local handler = require "kong.plugins.oidc.handler"
local openidc = require "kong.plugins.oidc.openidc"
local http = require("resty.http")
local function find_plugin()
    for plugin, err in kong.db.plugins:each(1000) do
      if err then
        return nil, err
      end
  
      if plugin.name == "oidc" then
        return plugin
      end
    end
  end

  local function openidc_parse_json_response(response, ignore_body_on_success)
    local ignore_body_on_success = ignore_body_on_success or false
  
    local err
    local res
  
    -- check the response from the OP
    if response.status ~= 200 then
      err = "response indicates failure, status=" .. response.status .. ", body=" .. response.body
    else
      if ignore_body_on_success then
        return nil, nil
      end
  
      -- decode the response and extract the JSON object
      res = cjson_s.decode(response.body)
  
      if not res then
        err = "JSON decoding failed"
      end
    end
  
    return res, err
  end

  return {
    ["/token"] = {
      POST = function(self)
        local plugin, err = find_plugin()
        if err then
          return kong.response.exit(500, { message = err })
        elseif not plugin then
          return kong.response.exit(404)
        end
  
        local conf = plugin.config

        local discovery_doc, err = openidc.get_discovery_doc(conf)
        if err then
          kong.log.err('Discovery document retrieval for Bearer JWT verify failed')
          return kong.response.exit(404)
        end
       
        local body = {
            grant_type = "password",
            client_id = conf.client_id,
            client_secret = conf.client_secret,
            username = tostring(self.params.username),
            password = tostring(self.params.password)
          }
        
        local headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded"
          }

        local httpc = http.new()
        local res, err = httpc:request_uri(discovery_doc.token_endpoint,  {
            method = "POST",
            body = ngx.encode_args(body),
            headers = headers,
            ssl_verify = (conf.ssl_verify ~= "no"),
            keepalive = (conf.keepalive ~= "no")
          })
          if not res then
            err = "accessing  endpoint (" .. discovery_doc.token_endpoint .. ") failed: " .. err
            kong.log.err( err)
            return kong.response.exit(404)
          end
        
        return kong.response.exit(200,   openidc_parse_json_response(res))
      end,
    }
  }