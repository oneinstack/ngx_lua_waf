-- waf core lib
require "config"

-- Get the client IP
function get_client_ip()
    local CLIENT_IP = ngx.req.get_headers(0)["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers(0)["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
end

-- Get the client user agent
function get_user_agent()
    local USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

-- Get WAF rule
function get_rule(rulefilename)
    local io = require "io"
    local RULE_PATH = config_rule_dir
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
    if RULE_FILE == nil then
        return
    end
    local RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,line)
    end
    RULE_FILE:close()
    return(RULE_TABLE)
end

-- WAF log record for json,(use logstash codec => json)
function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local io = require "io"
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.host
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 req_url = url,
                 attack_method = method,
                 req_data = data,
                 rule_tag = ruletag,
                 user_agent = USER_AGENT,
              }
    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_sec.log"
    local file = io.open(LOG_NAME,"a")
    if file == nil then
        return
    end
    file:write(LOG_LINE.."\n")
    file:flush()
    file:close()
end

-- test log
function write(logfile, msg)
    local fd,err = io.open(logfile,"a+")
    if fd == nil then
        ngx.log(ngx.ERR,"writefile msg : "..msg,err)
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
end

-- WAF return
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)
        ngx.exit(ngx.status)
    end
end

-- ip to inter
function ipToInt(str)
    local num = 0
    if str and type(str)=="string" then
        local o1,o2,o3,o4 = str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)" )
        num = 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
    end
    return num
end

-- inter to ip
function intToIp(n)
    if n then
        n = tonumber(n)
        local n1 = math.floor(n / (2^24)) 
        local n2 = math.floor((n - n1*(2^24)) / (2^16))
        local n3 = math.floor((n - n1*(2^24) - n2*(2^16)) / (2^8))
        local n4 = math.floor((n - n1*(2^24) - n2*(2^16) - n3*(2^8)))
        return n1.."."..n2.."."..n3.."."..n4 
    end
    return "0.0.0.0"
end

-- subnet
function subnet(ip, masklen)    
    if masklen == 32 then 
        return ip 
    end
    local ip = {string.match(ip, "(%d+).(%d+).(%d+).(%d+)")}
    local pos = math.floor((masklen)/8) + 1
    ip[pos] =  ip[pos] - ip[pos] % 2^(8-masklen%8)
    for i = pos + 1, #ip do
        ip[i] = 0
    end
    return table.concat(ip, ".")
end
