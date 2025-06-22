local http = require "http"
local json = require "cjson"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries the NVD CVE API 2.0 to find known vulnerabilities for CPE identifiers discovered during version detection.
This script requires the -sV (version detection) flag to identify software versions and generate CPE identifiers.

The script searches for Common Vulnerabilities and Exposures (CVEs) associated with the Common Platform Enumeration (CPE)
identifiers of detected services and software versions using the official NVD (National Vulnerability Database) API.

Example usage:
  nmap -sV --script nvd-cve <target>
  nmap -sV --script nvd-cve --script-args mincvss=7.0,apikey=<key> <target>

Script arguments:
  nvd-cve.mincvss: Minimum CVSS score threshold (default: 0.0)
  nvd-cve.apikey: NVD API key for higher rate limits (optional)
  nvd-cve.timeout: HTTP request timeout in seconds (default: 10)
  nvd-cve.maxcves: Maximum number of CVEs to display per service (default: 10)
]]

author = "Claude Code"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external", "intrusive"}

portrule = function(host, port)
    -- テスト用: より緩い条件で実行
    return port.state == "open" and port.version and (port.version.product or port.version.name)
end

-- Simple URL encoding function
local function url_encode(str)
    return str:gsub("[^%w%-%.%_%~]", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
end

-- Build CPE string from port version information
local function build_cpe_from_port(port)
    local cpes = {}
    
    if port.version and port.version.product then
        local vendor = port.version.vendor or "*"
        local product = port.version.product or "*"
        local version = port.version.version or "*"
        
        -- Map common product names to proper vendor names
        local vendor_mappings = {
            -- Web servers
            ["apache_httpd"] = "apache",
            ["httpd"] = "apache",
            ["apache"] = "apache",
            ["nginx"] = "nginx",
            ["microsoft_iis"] = "microsoft",
            ["iis"] = "microsoft",
            ["lighttpd"] = "lighttpd",
            ["caddy"] = "caddyserver",
            ["tomcat"] = "apache",
            ["jetty"] = "eclipse",
            ["node_js"] = "nodejs",
            ["express"] = "nodejs",
            
            -- SSH services
            ["openssh"] = "openbsd",
            ["ssh"] = "openbsd",
            ["dropbear"] = "dropbear_ssh_project",
            
            -- Database systems
            ["mysql"] = "mysql",
            ["mariadb"] = "mariadb",
            ["postgresql"] = "postgresql",
            ["postgres"] = "postgresql",
            ["mongodb"] = "mongodb",
            ["redis"] = "redis",
            ["sqlite"] = "sqlite",
            ["oracle"] = "oracle",
            ["mssql"] = "microsoft",
            ["sql_server"] = "microsoft",
            
            -- FTP services
            ["vsftpd"] = "vsftpd_project",
            ["proftpd"] = "proftpd",
            ["pure_ftpd"] = "pureftpd",
            ["filezilla"] = "filezilla_project",
            
            -- Mail services
            ["sendmail"] = "sendmail",
            ["postfix"] = "postfix",
            ["exim"] = "exim",
            ["dovecot"] = "dovecot",
            ["cyrus"] = "cmu",
            
            -- DNS services
            ["bind"] = "isc",
            ["named"] = "isc",
            ["dnsmasq"] = "thekelleys",
            ["unbound"] = "nlnet_labs",
            
            -- Network services
            ["snmp"] = "net_snmp",
            ["net_snmp"] = "net_snmp",
            ["ntp"] = "ntp",
            ["ntpd"] = "ntp",
            ["dhcp"] = "isc",
            ["dhcpd"] = "isc",
            
            -- Application frameworks
            ["php"] = "php",
            ["python"] = "python",
            ["java"] = "oracle",
            ["ruby"] = "ruby_lang",
            ["perl"] = "perl",
            ["node"] = "nodejs",
            
            -- Operating systems components
            ["linux"] = "linux",
            ["windows"] = "microsoft",
            ["freebsd"] = "freebsd",
            ["openbsd"] = "openbsd",
            ["netbsd"] = "netbsd",
            
            -- Network equipment
            ["cisco"] = "cisco",
            ["juniper"] = "juniper",
            ["mikrotik"] = "mikrotik",
            ["ubiquiti"] = "ui",
            
            -- Security tools
            ["nessus"] = "tenable",
            ["openvas"] = "greenbone",
            ["nmap"] = "nmap",
            ["wireshark"] = "wireshark",
            
            -- Content management systems
            ["wordpress"] = "wordpress",
            ["drupal"] = "drupal",
            ["joomla"] = "joomla",
            
            -- Virtualization
            ["vmware"] = "vmware",
            ["virtualbox"] = "oracle",
            ["docker"] = "docker",
            ["kubernetes"] = "kubernetes",
            
            -- Load balancers
            ["haproxy"] = "haproxy",
            ["f5"] = "f5",
            ["nginx_plus"] = "nginx",
            
            -- Monitoring tools
            ["nagios"] = "nagios",
            ["zabbix"] = "zabbix",
            ["cacti"] = "cacti",
            
            -- Version control
            ["git"] = "git_scm",
            ["svn"] = "apache",
            ["mercurial"] = "mercurial",
            
            -- Common services
            ["samba"] = "samba",
            ["cups"] = "apple",
            ["asterisk"] = "digium",
            ["openvpn"] = "openvpn"
        }
        
        -- Normalize product name
        if product ~= "*" then
            product = string.lower(product):gsub("[^%w]", "_")
        end
        
        -- Try to determine vendor from product if vendor is not available
        if vendor == "*" and product ~= "*" then
            vendor = vendor_mappings[product] or "*"
        end
        
        -- Normalize vendor name (preserve wildcards)
        if vendor ~= "*" then
            vendor = string.lower(vendor):gsub("[^%w]", "_")
        end
        
        -- Skip invalid CPEs where both vendor and product are wildcards
        if vendor ~= "*" or product ~= "*" then
            -- Create CPE 2.3 format
            local cpe = string.format("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
            table.insert(cpes, cpe)
            
            -- Also try without version for broader search
            if version ~= "*" then
                local cpe_no_version = string.format("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", vendor, product)
                table.insert(cpes, cpe_no_version)
            end
        end
    end
    
    return cpes
end

-- Query NVD CVE API for CPE
local function query_nvd_cve_api(cpe, apikey, timeout)
    local api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    local params = {
        ["cpeName"] = cpe,
        ["resultsPerPage"] = "20"
    }
    
    -- Build query string
    local query_params = {}
    for key, value in pairs(params) do
        table.insert(query_params, key .. "=" .. url_encode(value))
    end
    local query_string = table.concat(query_params, "&")
    local full_url = api_url .. "?" .. query_string
    
    -- Set up headers
    local headers = {
        ["User-Agent"] = "Nmap NSE nvd-cve script"
    }
    
    if apikey then
        headers["apiKey"] = apikey
    end
    
    -- Make HTTP request
    local response = http.get_url(full_url, {
        header = headers,
        timeout = timeout or 10000
    })
    
    if not response or response.status ~= 200 then
        return nil, "HTTP request failed"
    end
    
    local success, data = pcall(json.decode, response.body)
    if not success then
        return nil, "JSON parsing failed"
    end
    
    return data, nil
end

-- Extract and format vulnerability information
local function format_vulnerability_info(cve_data, min_cvss, max_cves)
    local vulnerabilities = {}
    
    if not cve_data.vulnerabilities then
        return vulnerabilities
    end
    
    local count = 0
    for _, vuln in ipairs(cve_data.vulnerabilities) do
        if count >= max_cves then
            break
        end
        
        local cve = vuln.cve
        if cve and cve.id then
            local cvss_score = 0.0
            local cvss_vector = ""
            
            -- Extract CVSS information (prefer v3, fallback to v2)
            if cve.metrics and cve.metrics.cvssMetricV31 and #cve.metrics.cvssMetricV31 > 0 then
                local metric = cve.metrics.cvssMetricV31[1]
                if metric.cvssData then
                    cvss_score = metric.cvssData.baseScore or 0.0
                    cvss_vector = metric.cvssData.vectorString or ""
                end
            elseif cve.metrics and cve.metrics.cvssMetricV30 and #cve.metrics.cvssMetricV30 > 0 then
                local metric = cve.metrics.cvssMetricV30[1]
                if metric.cvssData then
                    cvss_score = metric.cvssData.baseScore or 0.0
                    cvss_vector = metric.cvssData.vectorString or ""
                end
            elseif cve.metrics and cve.metrics.cvssMetricV2 and #cve.metrics.cvssMetricV2 > 0 then
                local metric = cve.metrics.cvssMetricV2[1]
                if metric.cvssData then
                    cvss_score = metric.cvssData.baseScore or 0.0
                    cvss_vector = metric.cvssData.vectorString or ""
                end
            end
            
            -- Check if CVSS score meets minimum threshold
            if cvss_score >= min_cvss then
                local description = ""
                if cve.descriptions and #cve.descriptions > 0 then
                    for _, desc in ipairs(cve.descriptions) do
                        if desc.lang == "en" then
                            description = desc.value
                            break
                        end
                    end
                end
                
                -- Truncate long descriptions
                if #description > 200 then
                    description = description:sub(1, 197) .. "..."
                end
                
                table.insert(vulnerabilities, {
                    id = cve.id,
                    cvss = cvss_score,
                    vector = cvss_vector,
                    description = description,
                    published = cve.published or "",
                    modified = cve.lastModified or ""
                })
                
                count = count + 1
            end
        end
    end
    
    -- Sort by CVSS score (highest first)
    table.sort(vulnerabilities, function(a, b) return a.cvss > b.cvss end)
    
    return vulnerabilities
end

-- Main action function
action = function(host, port)
    local apikey = stdnse.get_script_args(SCRIPT_NAME .. ".apikey")
    local min_cvss = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".mincvss")) or 0.0
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10
    local max_cves = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxcves")) or 10
    
    -- Build CPE identifiers from port information
    local cpes = build_cpe_from_port(port)
    
    if #cpes == 0 then
        return "No CPE identifiers could be generated from version information"
    end
    
    local all_vulnerabilities = {}
    local total_found = 0
    
    -- Query each CPE
    for _, cpe in ipairs(cpes) do
        stdnse.debug1("Querying NVD for CPE: %s", cpe)
        
        -- Add delay to respect rate limits (6 seconds without API key, 0.6 with key)
        local delay = apikey and 600 or 6000
        stdnse.sleep(delay / 1000)
        
        local cve_data, err = query_nvd_cve_api(cpe, apikey, timeout * 1000)
        if cve_data then
            local vulnerabilities = format_vulnerability_info(cve_data, min_cvss, max_cves)
            total_found = total_found + (cve_data.totalResults or 0)
            
            for _, vuln in ipairs(vulnerabilities) do
                table.insert(all_vulnerabilities, vuln)
            end
        else
            stdnse.debug1("Error querying CPE %s: %s", cpe, err or "unknown")
        end
    end
    
    -- Remove duplicates and limit results
    local seen = {}
    local unique_vulns = {}
    for _, vuln in ipairs(all_vulnerabilities) do
        if not seen[vuln.id] and #unique_vulns < max_cves then
            seen[vuln.id] = true
            table.insert(unique_vulns, vuln)
        end
    end
    
    -- Sort final results by CVSS score
    table.sort(unique_vulns, function(a, b) return a.cvss > b.cvss end)
    
    if #unique_vulns == 0 then
        return string.format("No vulnerabilities found (minimum CVSS: %.1f)", min_cvss)
    end
    
    -- Format output
    local output = {}
    table.insert(output, string.format("Found %d vulnerabilities (showing %d, total in NVD: %d)", 
                 #unique_vulns, math.min(#unique_vulns, max_cves), total_found))
    
    for _, vuln in ipairs(unique_vulns) do
        table.insert(output, string.format("  %s (CVSS: %.1f) %s", 
                     vuln.id, vuln.cvss, vuln.description))
    end
    
    -- Add CPE information
    table.insert(output, "")
    table.insert(output, "Queried CPEs:")
    for _, cpe in ipairs(cpes) do
        table.insert(output, "  " .. cpe)
    end
    
    return table.concat(output, "\n")
end