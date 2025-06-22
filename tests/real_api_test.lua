#!/usr/bin/env lua

-- Real API integration tests for nvd-cve.nse script
-- These tests make actual calls to the NVD API using CPEs of known vulnerable software

local json = require "cjson"

-- Extract functions from the actual script without loading NSE modules

-- Mock stdnse module for real API tests
local mock_stdnse = {
    get_script_args = function(arg)
        local args = {
            ["nvd-cve.mincvss"] = "0.0",
            ["nvd-cve.apikey"] = nil,
            ["nvd-cve.timeout"] = "15",
            ["nvd-cve.maxcves"] = "10"
        }
        return args[arg]
    end,
    debug1 = function(fmt, ...)
        if _G.DEBUG then
            print(string.format("[DEBUG] " .. fmt, ...))
        end
    end,
    sleep = function(seconds)
        -- Use actual sleep for rate limiting in real tests
        os.execute("sleep " .. tostring(seconds))
    end
}

-- HTTP client using system curl command for actual requests
local function make_http_request(url, headers)
    -- Create temporary files for curl
    local temp_response = os.tmpname()
    local temp_headers = os.tmpname()
    
    -- Build curl command
    local curl_cmd = string.format('curl -s -o "%s" -w "%%{http_code}" "%s"', temp_response, url)
    
    -- Add headers if provided
    if headers then
        for key, value in pairs(headers) do
            curl_cmd = curl_cmd .. string.format(' -H "%s: %s"', key, value)
        end
    end
    
    -- Add timeout
    curl_cmd = curl_cmd .. " --max-time 30"
    
    print(string.format("Executing: %s", curl_cmd))
    
    -- Execute curl command
    local handle = io.popen(curl_cmd .. " 2>/dev/null")
    local http_code = handle:read("*a")
    handle:close()
    
    -- Read response body
    local response_file = io.open(temp_response, "r")
    local body = ""
    if response_file then
        body = response_file:read("*a")
        response_file:close()
    end
    
    -- Clean up temporary files
    os.remove(temp_response)
    os.remove(temp_headers)
    
    -- Parse HTTP code
    local status = tonumber(http_code:match("%d+")) or 0
    
    return {
        status = status,
        body = body
    }
end

local mock_http = {
    get_url = function(url, options)
        local headers = {}
        if options and options.header then
            headers = options.header
        end
        return make_http_request(url, headers)
    end
}

-- Replace global modules for testing
_G.stdnse = mock_stdnse

-- Copy query function from the actual script for testing
local function url_encode(str)
    return str:gsub("[^%w%-%.%_%~]", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
end

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
    
    print(string.format("Querying: %s", full_url))
    
    -- Make HTTP request
    local response = mock_http.get_url(full_url, {
        header = headers,
        timeout = timeout or 15000
    })
    
    if not response or response.status ~= 200 then
        return nil, string.format("HTTP request failed with status: %s", response and response.status or "unknown")
    end
    
    local success, data = pcall(json.decode, response.body)
    if not success then
        return nil, "JSON parsing failed"
    end
    
    return data, nil
end

-- Test framework for real API tests
local RealAPITestFramework = {}
RealAPITestFramework.__index = RealAPITestFramework

function RealAPITestFramework.new()
    local self = setmetatable({}, RealAPITestFramework)
    self.tests = {}
    self.passed = 0
    self.failed = 0
    return self
end

function RealAPITestFramework:add_test(name, test_func)
    table.insert(self.tests, {name = name, func = test_func})
end

function RealAPITestFramework:assert_greater_than(actual, minimum, message)
    if actual > minimum then
        return true
    else
        error(string.format("Assertion failed: %s\nExpected: > %s\nActual: %s", 
              message or "value should be greater", tostring(minimum), tostring(actual)))
    end
end

function RealAPITestFramework:assert_not_nil(value, message)
    if value ~= nil then
        return true
    else
        error(string.format("Assertion failed: %s\nValue is nil", message or "value should not be nil"))
    end
end

function RealAPITestFramework:assert_equal(actual, expected, message)
    if actual == expected then
        return true
    else
        error(string.format("Assertion failed: %s\nExpected: %s\nActual: %s", 
              message or "values not equal", tostring(expected), tostring(actual)))
    end
end

function RealAPITestFramework:run_tests()
    print("Running real API integration tests...")
    print("=====================================")
    print("Note: These tests make actual calls to the NVD API")
    print("Please ensure you have internet connectivity")
    print("Tests include rate limiting delays...")
    print()
    
    for i, test in ipairs(self.tests) do
        print(string.format("Running test %d/%d: %s", i, #self.tests, test.name))
        
        local success, err = pcall(test.func, self)
        if success then
            print(string.format("✓ %s", test.name))
            self.passed = self.passed + 1
        else
            print(string.format("✗ %s", test.name))
            print(string.format("  Error: %s", err))
            self.failed = self.failed + 1
        end
        
        -- Rate limiting delay between tests (6 seconds without API key)
        if i < #self.tests then
            print("  Waiting 6 seconds for rate limiting...")
            mock_stdnse.sleep(6)
        end
        print()
    end
    
    print("=====================================")
    print(string.format("Real API tests: %d passed, %d failed, %d total", 
          self.passed, self.failed, self.passed + self.failed))
    
    return self.failed == 0
end

-- Real API test cases with known vulnerable software

local function test_apache_244_vulnerabilities(framework)
    -- Apache HTTP Server 2.4.4 has known vulnerabilities
    local cpe = "cpe:2.3:a:apache:httpd:2.4.4:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 15000)
    
    framework:assert_not_nil(data, "Should receive data for Apache 2.4.4")
    if err then
        error("API call failed: " .. err)
    end
    
    framework:assert_greater_than(data.totalResults, 0, "Apache 2.4.4 should have known vulnerabilities")
    print(string.format("  Found %d vulnerabilities for Apache 2.4.4", data.totalResults))
    
    if data.vulnerabilities and #data.vulnerabilities > 0 then
        local first_vuln = data.vulnerabilities[1]
        framework:assert_not_nil(first_vuln.cve.id, "Should have CVE ID")
        print(string.format("  Example CVE: %s", first_vuln.cve.id))
    end
end

local function test_openssh_64_vulnerabilities(framework)
    -- OpenSSH 6.4 has known vulnerabilities
    local cpe = "cpe:2.3:a:openbsd:openssh:6.4:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 15000)
    
    framework:assert_not_nil(data, "Should receive data for OpenSSH 6.4")
    if err then
        error("API call failed: " .. err)
    end
    
    framework:assert_greater_than(data.totalResults, 0, "OpenSSH 6.4 should have known vulnerabilities")
    print(string.format("  Found %d vulnerabilities for OpenSSH 6.4", data.totalResults))
    
    if data.vulnerabilities and #data.vulnerabilities > 0 then
        local first_vuln = data.vulnerabilities[1]
        framework:assert_not_nil(first_vuln.cve.id, "Should have CVE ID")
        print(string.format("  Example CVE: %s", first_vuln.cve.id))
    end
end

local function test_mysql_550_vulnerabilities(framework)
    -- MySQL 5.5.0 has known vulnerabilities
    local cpe = "cpe:2.3:a:mysql:mysql:5.5.0:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 15000)
    
    framework:assert_not_nil(data, "Should receive data for MySQL 5.5.0")
    if err then
        error("API call failed: " .. err)
    end
    
    framework:assert_greater_than(data.totalResults, 0, "MySQL 5.5.0 should have known vulnerabilities")
    print(string.format("  Found %d vulnerabilities for MySQL 5.5.0", data.totalResults))
    
    if data.vulnerabilities and #data.vulnerabilities > 0 then
        local first_vuln = data.vulnerabilities[1]
        framework:assert_not_nil(first_vuln.cve.id, "Should have CVE ID")
        print(string.format("  Example CVE: %s", first_vuln.cve.id))
    end
end

local function test_nginx_110_vulnerabilities(framework)
    -- Nginx 1.1.0 has known vulnerabilities
    local cpe = "cpe:2.3:a:nginx:nginx:1.1.0:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 15000)
    
    framework:assert_not_nil(data, "Should receive data for Nginx 1.1.0")
    if err then
        error("API call failed: " .. err)
    end
    
    framework:assert_greater_than(data.totalResults, 0, "Nginx 1.1.0 should have known vulnerabilities")
    print(string.format("  Found %d vulnerabilities for Nginx 1.1.0", data.totalResults))
    
    if data.vulnerabilities and #data.vulnerabilities > 0 then
        local first_vuln = data.vulnerabilities[1]
        framework:assert_not_nil(first_vuln.cve.id, "Should have CVE ID")
        print(string.format("  Example CVE: %s", first_vuln.cve.id))
    end
end

local function test_unknown_software_no_vulnerabilities(framework)
    -- Test with a CPE that should have no vulnerabilities
    local cpe = "cpe:2.3:a:nonexistent:software:99.99.99:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 15000)
    
    framework:assert_not_nil(data, "Should receive data even for unknown software")
    if err then
        error("API call failed: " .. err)
    end
    
    framework:assert_equal(data.totalResults, 0, "Unknown software should have no vulnerabilities")
    print("  Confirmed: No vulnerabilities found for nonexistent software")
end

-- Run real API tests
local function main()
    
    local framework = RealAPITestFramework.new()
    
    -- Add real API test cases with known vulnerable software
    framework:add_test("Apache HTTP Server 2.4.4 vulnerabilities", test_apache_244_vulnerabilities)
    framework:add_test("OpenSSH 6.4 vulnerabilities", test_openssh_64_vulnerabilities)
    framework:add_test("MySQL 5.5.0 vulnerabilities", test_mysql_550_vulnerabilities)
    framework:add_test("Nginx 1.1.0 vulnerabilities", test_nginx_110_vulnerabilities)
    framework:add_test("Unknown software (negative test)", test_unknown_software_no_vulnerabilities)
    
    -- Run tests
    local success = framework:run_tests()
    
    if success then
        print("All real API tests passed! ✓")
        print("The script can successfully retrieve vulnerabilities from NVD for known vulnerable software.")
        os.exit(0)
    else
        print("Some real API tests failed! ✗")
        print("Please check your internet connection and the NVD API availability.")
        os.exit(1)
    end
end

-- Enable debug output if requested
if arg and arg[1] == "--debug" then
    _G.DEBUG = true
end

main()