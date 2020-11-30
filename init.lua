-- WAF Action
require "config"
require "lib"

-- args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

-- allow white ip
function white_ip_check()
     if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule("whiteip")
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" then
                    RULE_IP_START = 9999999999
                    RULE_IP_END = 9999999999
                    if string.find(rule, ",") then
                        local s,l = string.find(rule, ",")
                        local num = 0
                        num = l - 1
                        RULE_IP_START = ipToInt(string.sub(rule, 1, num))
                        num = l + 1
                        RULE_IP_END = ipToInt(string.sub(rule, num))
                    elseif string.find(rule, "/") then
                        local s,l = string.find(rule, "/")
                        local num = 0
                        num = l - 1
                        RULE_IP = string.sub(rule, 1, num)
                        num = l + 1
                        RULE_END = string.sub(rule, num)
                        RULE_IP_START = ipToInt(subnet(RULE_IP, RULE_END))
                        if tonumber(RULE_END) ~= '' and tonumber(RULE_END) < 32 then
                            RULE_IP_END = RULE_IP_START + 2^(32 - RULE_END) - 1
                        else
                            RULE_IP_END = RULE_IP_START
                        end
                    elseif (rule ~= 'unknown') then
                        RULE_IP_START = ipToInt(rule)
                        RULE_IP_END = RULE_IP_START
                    end
                end
                local Num_White_IP = ipToInt(get_client_ip())
                if rule ~= "" and RULE_IP_START <= Num_White_IP and Num_White_IP <= RULE_IP_END then
                    log_record("White_IP",ngx.var.request_uri,"_",rule)           
                    return true
                end
            end
        end
    end
end

-- deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule("blackip")
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" then
                    RULE_IP_START = 9999999999
                    RULE_IP_END = 9999999999
                    if string.find(rule, ",") then
                        local s,l = string.find(rule, ",")
                        local num = 0
                        num = l - 1
                        RULE_IP_START = ipToInt(string.sub(rule, 1, num))
                        num = l + 1                        
                        RULE_IP_END = ipToInt(string.sub(rule, num))                        
                    elseif string.find(rule, "/") then
                        local s,l = string.find(rule, "/")
                        local num = 0
                        num = l - 1                        
                        RULE_IP = string.sub(rule, 1, num)
                        num = l + 1                        
                        RULE_END = string.sub(rule, num)                        
                        RULE_IP_START = ipToInt(subnet(RULE_IP, RULE_END))
                        if tonumber(RULE_END) ~= '' and tonumber(RULE_END) < 32 then
                            RULE_IP_END = RULE_IP_START + 2^(32 - RULE_END) - 1
                        else 
                            RULE_IP_END = RULE_IP_START
                        end
                    elseif (rule ~= 'unknown') then
                        RULE_IP_START = ipToInt(rule)
                        RULE_IP_END = RULE_IP_START                        
                    end                    
                end
                local Num_Black_IP = ipToInt(get_client_ip())
                if rule ~= "" and RULE_IP_START <= Num_Black_IP and Num_Black_IP <= RULE_IP_END then
                    -- log_record('BlackList_IP',ngx.var.request_uri,"_","_")                    
                    if config_waf_enable == "on" then
                        ngx.header.content_type = "text/html"
                        ngx.say('Your IP blacklist, Please contact the administrator! ')
                        return true
                    end
                end
            end
        end
    end
end

-- allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule("whiteurl")
        local REQ_URI = string.lower(ngx.var.request_uri)
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" then
                    local REQ_URI_LEN = string.len(REQ_URI)
                    local rule_str = string.sub(rule,1,2)
                    local from, to, err = rulematch(REQ_URI,string.lower(rule),"jo")
                    if rule_str == "\\." then
                        local wfrom, wto, werr = rulematch(unescape(REQ_URI),"%?","jo")
                        if from and REQ_URI_LEN == to and wfrom == nil then
                            return true
                        end
                    elseif from and rule_str == "\\/" and from == 1 then
                        return true
                    elseif from and from == 2 then
                        return true
                    end
                end
            end
        end
    end
end

-- deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local USER_AGENT = get_user_agent()
        local ARGS = ngx.var.args or ""

        local ATTACK_URL = ngx.var.host .. ngx.var.uri
        -- local ATTACK_URL = ngx.var.host .. ngx.var.request_uri
        -- local ATTACK_URL = ngx.var.host .. ngx.var.uri .. '?' .. ARGS

        local CC_TOKEN = get_client_ip() .. "." .. ngx.md5(string.lower(ATTACK_URL) .. USER_AGENT)
        local limit = ngx.shared.limit
        local CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        local CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        if req then
            -- write("/data/wwwlogs/info.log",CC_TOKEN .."\t".. ATTACK_URL .. "\t".. "req: " .. req .."\n")
            if req > CCcount then
                log_record("CC_Attack",ngx.var.request_uri,"-","-")
                log_post_http("CC_Attack",ngx.var.request_uri,"-","-")
                if config_waf_enable == "on" then
                    local source = ngx.encode_base64(ngx.var.scheme.."://"..ngx.var.host..ngx.var.request_uri)
                    local dest = '/captcha-waf.html' .. '?continue=' .. source
                    local CCcountcode,_ = math.modf(CCcount/2);
                    limit:set(CC_TOKEN,CCcountcode)
                    ngx.redirect(dest,302)
                end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

-- deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule("cookie")
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(string.lower(USER_COOKIE),string.lower(rule),"jo") then
                    log_record("Deny_Cookie",ngx.var.request_uri,"-",rule)                    
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
		end
    end
    return false
end

-- deny url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule("blackurl")
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(string.lower(REQ_URI),string.lower(rule),"jo") then
                log_record("Deny_URL",REQ_URI,"-",rule)                
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args')
        for _,rule in pairs(ARGS_RULES) do
            --local REQ_ARGS = ngx.req.get_uri_args()
			local REQ_ARGS, err = ngx.req.get_uri_args()
			if err == "truncated" then				
				log_record("URL_ARGS_MANY",ngx.var.request_uri,"-",rule)
				if config_waf_enable == "on" then
					waf_output()
					return true
				end
			end
            for key, val in pairs(REQ_ARGS) do
                if type(val) == "table" then
                    ARGS_DATA = string.lower(table.concat(val, " "))
                else
                    ARGS_DATA = string.lower(val)
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),string.lower(rule),"jo") then
                    log_record("Deny_URL_Args",ngx.var.request_uri,"-",rule)                    
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule("useragent")
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(string.lower(USER_AGENT),string.lower(rule),"jo") then
                    log_record("Deny_USER_AGENT",ngx.var.request_uri,"-",rule)                    
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- deny post
function post_attack_check()
    if config_post_check == "on" and ngx.var.request_method == "POST" then
        ngx.req.read_body()
        local POST_RULES = get_rule("post")
        local receive_headers = ngx.req.get_headers()
        if string.sub(receive_headers["content-type"],1,20) == "multipart/form-data;" then
            info_type = "Deny_MULTIPART_POST"
            local body_data = ngx.req.get_body_data()
            content_type = receive_headers["content-type"]
            if not body_data then
                local body_data_file = ngx.req.get_body_file()
                if body_data_file then
                    local fh, err = io.open(body_data_file,"r")
                    if fh then
                        fh:seek("set")
                        body_data = fh:read("*a")
                        fh:close()
                    end
                end
            end
            bi, bj = string.find(content_type, 'boundary=')
            boundary = string.sub(content_type, bj+1)
            if body_data ~= "" and boundary ~= "" then
                boundary = '--'..boundary
                REQ_POST = {}
                local i = 0
                local b = string.len(boundary)
                while true do
                    x = i + b + 1;
                    i,j = string.find(body_data, boundary, i + b + 1)
                    if i == nil then break end
                    body = string.sub(body_data, x, i-1)
                    Content_Disposition = body:match('Content%-Disposition:.-\r\n')
                    file_type = body:match("Content%-Type:.-\r\n")
                    if file_type ~= nil and Content_Disposition ~= nil then
                        table.insert(REQ_POST, file_type)
                        table.insert(REQ_POST, Content_Disposition)
                    else
                        table.insert(REQ_POST, body)
                    end
                end
            else
                log_record("Deny__MULTIPART_POST",ngx.var.request_uri,"Empty",rule)                    
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        else
            info_type = "Deny_POST"
            REQ_POST, err = ngx.req.get_post_args()
            if err == "truncated" then
                log_record("DENY_POST_MANY",ngx.var.request_uri,"-",rule)
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
        for _,rule in pairs(POST_RULES) do
            for key, val in pairs(REQ_POST) do
                if type(val) == "table" then
                    POST_DATA = string.lower(table.concat(val, " "))
                elseif type(val) == "boolean" then
                    POST_DATA = nil
                else
                    POST_DATA = string.lower(val)
                end
                if POST_DATA and rule ~="" and rulematch(unescape(POST_DATA),string.lower(rule),"jo") then
                    log_record(info_type,ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
        return true
    end
    return false
end