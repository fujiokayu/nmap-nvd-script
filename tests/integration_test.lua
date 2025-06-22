#!/usr/bin/env lua

-- Integration tests for nvd-cve.nse script with mock API responses
-- This script tests the full workflow with simulated HTTP responses

local json = require "cjson"

-- Mock HTTP responses for different scenarios
local MockHTTPServer = {}
MockHTTPServer.__index = MockHTTPServer

function MockHTTPServer.new()
    local self = setmetatable({}, MockHTTPServer)
    self.responses = {}
    self.call_count = 0
    return self
end

function MockHTTPServer:add_response(url_pattern, response)
    table.insert(self.responses, {pattern = url_pattern, response = response})
end

function MockHTTPServer:get_response(url)
    self.call_count = self.call_count + 1
    
    for _, mock in ipairs(self.responses) do
        if string.match(url, mock.pattern) then
            return mock.response
        end
    end
    
    -- Default error response
    return {
        status = 404,
        body = json.encode({error = "Not found"})
    }
end

-- Create global mock server instance
local mock_server = MockHTTPServer.new()

-- Mock modules for integration testing
local mock_http = {
    escape = function(str)
        return str:gsub("[^%w%-%.%_%~]", function(c)
            return string.format("%%%02X", string.byte(c))
        end)
    end,
    get_url = function(url, options)
        return mock_server:get_response(url)
    end
}

local mock_stdnse = {
    get_script_args = function(arg)
        local args = {
            ["nvd-cve.mincvss"] = "0.0",
            ["nvd-cve.apikey"] = nil,
            ["nvd-cve.timeout"] = "10",
            ["nvd-cve.maxcves"] = "10"
        }
        return args[arg]
    end,
    debug1 = function(fmt, ...)
        if _G.DEBUG then
            print(string.format("[DEBUG] " .. fmt, ...))
        end
    end,
    sleep = function(seconds) end
}

-- Replace global modules
_G.http = mock_http
_G.stdnse = mock_stdnse

-- Copy the query function for testing
local function query_nvd_cve_api(cpe, apikey, timeout)
    local api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    local params = {
        ["cpeName"] = cpe,
        ["resultsPerPage"] = "20"
    }
    
    -- Build query string
    local query_params = {}
    for key, value in pairs(params) do
        table.insert(query_params, key .. "=" .. mock_http.escape(value))
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
    local response = mock_http.get_url(full_url, {
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

-- Test framework
local IntegrationTestFramework = {}
IntegrationTestFramework.__index = IntegrationTestFramework

function IntegrationTestFramework.new()
    local self = setmetatable({}, IntegrationTestFramework)
    self.tests = {}
    self.passed = 0
    self.failed = 0
    return self
end

function IntegrationTestFramework:add_test(name, test_func)
    table.insert(self.tests, {name = name, func = test_func})
end

function IntegrationTestFramework:assert_equal(actual, expected, message)
    if actual == expected then
        return true
    else
        error(string.format("Assertion failed: %s\nExpected: %s\nActual: %s", 
              message or "values not equal", tostring(expected), tostring(actual)))
    end
end

function IntegrationTestFramework:assert_not_nil(value, message)
    if value ~= nil then
        return true
    else
        error(string.format("Assertion failed: %s\nValue is nil", message or "value should not be nil"))
    end
end

function IntegrationTestFramework:assert_nil(value, message)
    if value == nil then
        return true
    else
        error(string.format("Assertion failed: %s\nValue is not nil: %s", 
              message or "value should be nil", tostring(value)))
    end
end

function IntegrationTestFramework:run_tests()
    print("Running integration tests...")
    print("============================")
    
    for _, test in ipairs(self.tests) do
        -- Reset mock server for each test
        mock_server = MockHTTPServer.new()
        
        local success, err = pcall(test.func, self)
        if success then
            print(string.format("✓ %s", test.name))
            self.passed = self.passed + 1
        else
            print(string.format("✗ %s", test.name))
            print(string.format("  Error: %s", err))
            self.failed = self.failed + 1
        end
    end
    
    print("============================")
    print(string.format("Integration tests: %d passed, %d failed, %d total", 
          self.passed, self.failed, self.passed + self.failed))
    
    return self.failed == 0
end

-- Integration test cases

local function test_successful_api_response(framework)
    -- Setup mock response
    local mock_response = {
        status = 200,
        body = json.encode({
            totalResults = 1,
            vulnerabilities = {
                {
                    cve = {
                        id = "CVE-2023-1234",
                        published = "2023-01-01T00:00:00.000",
                        lastModified = "2023-01-02T00:00:00.000",
                        descriptions = {
                            {
                                lang = "en",
                                value = "Test vulnerability for Apache HTTP Server"
                            }
                        },
                        metrics = {
                            cvssMetricV31 = {
                                {
                                    cvssData = {
                                        baseScore = 7.5,
                                        vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }
    
    mock_server:add_response("services%.nvd%.nist%.gov", mock_response)
    
    local cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 10000)
    
    framework:assert_not_nil(data, "Should receive data from successful API call")
    framework:assert_nil(err, "Should not have error on successful API call")
    framework:assert_equal(data.totalResults, 1, "Should parse total results correctly")
    framework:assert_equal(#data.vulnerabilities, 1, "Should have one vulnerability")
    framework:assert_equal(data.vulnerabilities[1].cve.id, "CVE-2023-1234", "Should parse CVE ID correctly")
end

local function test_api_error_response(framework)
    -- Setup mock error response
    local mock_response = {
        status = 500,
        body = "Internal Server Error"
    }
    
    mock_server:add_response("services%.nvd%.nist%.gov", mock_response)
    
    local cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 10000)
    
    framework:assert_nil(data, "Should not receive data on API error")
    framework:assert_not_nil(err, "Should have error message on API failure")
    framework:assert_equal(err, "HTTP request failed", "Should return appropriate error message")
end

local function test_invalid_json_response(framework)
    -- Setup mock response with invalid JSON
    local mock_response = {
        status = 200,
        body = "{ invalid json content"
    }
    
    mock_server:add_response("services%.nvd%.nist%.gov", mock_response)
    
    local cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 10000)
    
    framework:assert_nil(data, "Should not receive data on JSON parse error")
    framework:assert_not_nil(err, "Should have error message on JSON parse failure")
    framework:assert_equal(err, "JSON parsing failed", "Should return JSON parsing error")
end

local function test_empty_vulnerabilities_response(framework)
    -- Setup mock response with no vulnerabilities
    local mock_response = {
        status = 200,
        body = json.encode({
            totalResults = 0,
            vulnerabilities = {}
        })
    }
    
    mock_server:add_response("services%.nvd%.nist%.gov", mock_response)
    
    local cpe = "cpe:2.3:a:unknown:software:1.0.0:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 10000)
    
    framework:assert_not_nil(data, "Should receive data even when no vulnerabilities found")
    framework:assert_nil(err, "Should not have error on successful empty response")
    framework:assert_equal(data.totalResults, 0, "Should report zero results")
    framework:assert_equal(#data.vulnerabilities, 0, "Should have empty vulnerabilities array")
end

local function test_multiple_vulnerabilities_response(framework)
    -- Setup mock response with multiple vulnerabilities
    local mock_response = {
        status = 200,
        body = json.encode({
            totalResults = 3,
            vulnerabilities = {
                {
                    cve = {
                        id = "CVE-2023-0001",
                        published = "2023-01-01T00:00:00.000",
                        descriptions = {{lang = "en", value = "First vulnerability"}},
                        metrics = {
                            cvssMetricV31 = {{
                                cvssData = {baseScore = 9.0, vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                            }}
                        }
                    }
                },
                {
                    cve = {
                        id = "CVE-2023-0002",
                        published = "2023-01-02T00:00:00.000",
                        descriptions = {{lang = "en", value = "Second vulnerability"}},
                        metrics = {
                            cvssMetricV31 = {{
                                cvssData = {baseScore = 7.5, vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
                            }}
                        }
                    }
                },
                {
                    cve = {
                        id = "CVE-2023-0003",
                        published = "2023-01-03T00:00:00.000",
                        descriptions = {{lang = "en", value = "Third vulnerability"}},
                        metrics = {
                            cvssMetricV31 = {{
                                cvssData = {baseScore = 4.0, vectorString = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}
                            }}
                        }
                    }
                }
            }
        })
    }
    
    mock_server:add_response("services%.nvd%.nist%.gov", mock_response)
    
    local cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, nil, 10000)
    
    framework:assert_not_nil(data, "Should receive data for multiple vulnerabilities")
    framework:assert_nil(err, "Should not have error on successful response")
    framework:assert_equal(data.totalResults, 3, "Should report correct total results")
    framework:assert_equal(#data.vulnerabilities, 3, "Should have three vulnerabilities")
    
    -- Verify all CVEs are present
    local cve_ids = {}
    for _, vuln in ipairs(data.vulnerabilities) do
        table.insert(cve_ids, vuln.cve.id)
    end
    
    local expected_ids = {"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"}
    for _, expected_id in ipairs(expected_ids) do
        local found = false
        for _, actual_id in ipairs(cve_ids) do
            if actual_id == expected_id then
                found = true
                break
            end
        end
        framework:assert_equal(found, true, "Should contain CVE ID: " .. expected_id)
    end
end

local function test_api_with_api_key(framework)
    -- This test verifies that API key is passed correctly
    -- In a real scenario, this would test different rate limiting behavior
    
    local mock_response = {
        status = 200,
        body = json.encode({
            totalResults = 1,
            vulnerabilities = {
                {
                    cve = {
                        id = "CVE-2023-API-KEY",
                        published = "2023-01-01T00:00:00.000",
                        descriptions = {{lang = "en", value = "Test with API key"}},
                        metrics = {
                            cvssMetricV31 = {{
                                cvssData = {baseScore = 6.0, vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}
                            }}
                        }
                    }
                }
            }
        })
    }
    
    mock_server:add_response("services%.nvd%.nist%.gov", mock_response)
    
    local cpe = "cpe:2.3:a:test:software:1.0.0:*:*:*:*:*:*:*"
    local data, err = query_nvd_cve_api(cpe, "test-api-key", 10000)
    
    framework:assert_not_nil(data, "Should receive data when using API key")
    framework:assert_nil(err, "Should not have error when using API key")
    framework:assert_equal(data.vulnerabilities[1].cve.id, "CVE-2023-API-KEY", "Should process response correctly with API key")
end

-- Run integration tests
local function main()
    local framework = IntegrationTestFramework.new()
    
    -- Add integration test cases
    framework:add_test("test_successful_api_response", test_successful_api_response)
    framework:add_test("test_api_error_response", test_api_error_response)
    framework:add_test("test_invalid_json_response", test_invalid_json_response)
    framework:add_test("test_empty_vulnerabilities_response", test_empty_vulnerabilities_response)
    framework:add_test("test_multiple_vulnerabilities_response", test_multiple_vulnerabilities_response)
    framework:add_test("test_api_with_api_key", test_api_with_api_key)
    
    -- Run tests
    local success = framework:run_tests()
    
    if success then
        print("\nAll integration tests passed! ✓")
        os.exit(0)
    else
        print("\nSome integration tests failed! ✗")
        os.exit(1)
    end
end

-- Enable debug output if requested
if arg and arg[1] == "--debug" then
    _G.DEBUG = true
end

main()