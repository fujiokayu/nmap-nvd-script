#!/usr/bin/env lua

-- Test framework for nvd-cve.nse script
-- This script tests the core functions of the NSE script

-- Load required modules
local json = require "cjson"

-- Mock nmap modules for testing
local mock_nmap = {
    get_port_state = function() return "open" end,
    set_port_state = function() end,
    set_port_version = function() end
}

local mock_stdnse = {
    get_script_args = function(arg)
        local args = {
            ["nvd-cve.mincvss"] = "5.0",
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

local mock_shortport = {
    version_port_or_service = function()
        return function(host, port) return true end
    end
}

local mock_http = {
    escape = function(str)
        return str:gsub("[^%w%-%.%_%~]", function(c)
            return string.format("%%%02X", string.byte(c))
        end)
    end,
    get_url = function(url, options)
        -- Mock successful HTTP response
        return {
            status = 200,
            body = json.encode({
                totalResults = 2,
                vulnerabilities = {
                    {
                        cve = {
                            id = "CVE-2023-1234",
                            published = "2023-01-01T00:00:00.000",
                            lastModified = "2023-01-02T00:00:00.000",
                            descriptions = {
                                {
                                    lang = "en",
                                    value = "Test vulnerability description for unit testing"
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
                    },
                    {
                        cve = {
                            id = "CVE-2023-5678",
                            published = "2023-02-01T00:00:00.000",
                            lastModified = "2023-02-02T00:00:00.000",
                            descriptions = {
                                {
                                    lang = "en",
                                    value = "Another test vulnerability with lower CVSS score"
                                }
                            },
                            metrics = {
                                cvssMetricV31 = {
                                    {
                                        cvssData = {
                                            baseScore = 4.0,
                                            vectorString = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            })
        }
    end
}

-- Replace global modules with mocks
_G.nmap = mock_nmap
_G.stdnse = mock_stdnse
_G.shortport = mock_shortport
_G.http = mock_http

-- Load the script functions (we need to extract them for testing)
-- Since we can't directly require the .nse file, we'll recreate the functions here

-- Function under test: build_cpe_from_port
local function build_cpe_from_port(port)
    local cpes = {}
    
    if port.version and port.version.product then
        local vendor = port.version.vendor or "*"
        local product = port.version.product or "*"
        local version = port.version.version or "*"
        
        -- Normalize vendor and product names (preserve wildcards)
        if vendor ~= "*" then
            vendor = string.lower(vendor):gsub("[^%w]", "_")
        end
        if product ~= "*" then
            product = string.lower(product):gsub("[^%w]", "_")
        end
        
        -- Create CPE 2.3 format
        local cpe = string.format("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
        table.insert(cpes, cpe)
        
        -- Also try without version for broader search
        if version ~= "*" then
            local cpe_no_version = string.format("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", vendor, product)
            table.insert(cpes, cpe_no_version)
        end
    end
    
    return cpes
end

-- Function under test: format_vulnerability_info
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

-- Test framework
local TestFramework = {}
TestFramework.__index = TestFramework

function TestFramework.new()
    local self = setmetatable({}, TestFramework)
    self.tests = {}
    self.passed = 0
    self.failed = 0
    return self
end

function TestFramework:add_test(name, test_func)
    table.insert(self.tests, {name = name, func = test_func})
end

function TestFramework:assert_equal(actual, expected, message)
    if actual == expected then
        return true
    else
        error(string.format("Assertion failed: %s\nExpected: %s\nActual: %s", 
              message or "values not equal", tostring(expected), tostring(actual)))
    end
end

function TestFramework:assert_not_nil(value, message)
    if value ~= nil then
        return true
    else
        error(string.format("Assertion failed: %s\nValue is nil", message or "value should not be nil"))
    end
end

function TestFramework:assert_true(value, message)
    if value == true then
        return true
    else
        error(string.format("Assertion failed: %s\nValue is not true: %s", 
              message or "value should be true", tostring(value)))
    end
end

function TestFramework:run_tests()
    print("Running tests...")
    print("================")
    
    for _, test in ipairs(self.tests) do
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
    
    print("================")
    print(string.format("Tests: %d passed, %d failed, %d total", 
          self.passed, self.failed, self.passed + self.failed))
    
    return self.failed == 0
end

-- Test cases
local function test_build_cpe_from_port_with_complete_info(framework)
    local port = {
        version = {
            vendor = "Apache",
            product = "HTTP Server",
            version = "2.4.41"
        }
    }
    
    local cpes = build_cpe_from_port(port)
    
    framework:assert_equal(#cpes, 2, "Should generate 2 CPEs")
    framework:assert_equal(cpes[1], "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*", "First CPE should include version")
    framework:assert_equal(cpes[2], "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "Second CPE should be version wildcard")
end

local function test_build_cpe_from_port_with_missing_vendor(framework)
    local port = {
        version = {
            product = "nginx",
            version = "1.18.0"
        }
    }
    
    local cpes = build_cpe_from_port(port)
    
    framework:assert_equal(#cpes, 2, "Should generate 2 CPEs even without vendor")
    framework:assert_equal(cpes[1], "cpe:2.3:a:*:nginx:1.18.0:*:*:*:*:*:*:*", "Should use wildcard for missing vendor")
end

local function test_build_cpe_from_port_no_version_info(framework)
    local port = {}
    
    local cpes = build_cpe_from_port(port)
    
    framework:assert_equal(#cpes, 0, "Should generate no CPEs without version info")
end

local function test_format_vulnerability_info_with_filtering(framework)
    local mock_data = {
        vulnerabilities = {
            {
                cve = {
                    id = "CVE-2023-1234",
                    published = "2023-01-01T00:00:00.000",
                    descriptions = {{lang = "en", value = "High severity vulnerability"}},
                    metrics = {
                        cvssMetricV31 = {{
                            cvssData = {
                                baseScore = 8.5,
                                vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                            }
                        }}
                    }
                }
            },
            {
                cve = {
                    id = "CVE-2023-5678",
                    published = "2023-02-01T00:00:00.000",
                    descriptions = {{lang = "en", value = "Low severity vulnerability"}},
                    metrics = {
                        cvssMetricV31 = {{
                            cvssData = {
                                baseScore = 3.0,
                                vectorString = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
                            }
                        }}
                    }
                }
            }
        }
    }
    
    local vulns = format_vulnerability_info(mock_data, 5.0, 10)
    
    framework:assert_equal(#vulns, 1, "Should filter out low CVSS vulnerabilities")
    framework:assert_equal(vulns[1].id, "CVE-2023-1234", "Should keep high CVSS vulnerability")
    framework:assert_equal(vulns[1].cvss, 8.5, "CVSS score should be preserved")
end

local function test_format_vulnerability_info_max_limit(framework)
    local mock_data = {
        vulnerabilities = {}
    }
    
    -- Generate test data with 5 vulnerabilities
    for i = 1, 5 do
        table.insert(mock_data.vulnerabilities, {
            cve = {
                id = "CVE-2023-" .. string.format("%04d", i),
                published = "2023-01-01T00:00:00.000",
                descriptions = {{lang = "en", value = "Test vulnerability " .. i}},
                metrics = {
                    cvssMetricV31 = {{
                        cvssData = {
                            baseScore = 5.0 + i,
                            vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                        }
                    }}
                }
            }
        })
    end
    
    local vulns = format_vulnerability_info(mock_data, 0.0, 3)
    
    framework:assert_equal(#vulns, 3, "Should limit results to max_cves parameter")
    -- Should be sorted by CVSS score (highest first)
    framework:assert_true(vulns[1].cvss >= vulns[2].cvss, "Results should be sorted by CVSS score")
    framework:assert_true(vulns[2].cvss >= vulns[3].cvss, "Results should be sorted by CVSS score")
end

local function test_format_vulnerability_info_empty_data(framework)
    local mock_data = {}
    
    local vulns = format_vulnerability_info(mock_data, 0.0, 10)
    
    framework:assert_equal(#vulns, 0, "Should handle empty data gracefully")
end

local function test_format_vulnerability_info_long_description(framework)
    local long_description = string.rep("This is a very long vulnerability description. ", 10)
    
    local mock_data = {
        vulnerabilities = {
            {
                cve = {
                    id = "CVE-2023-1234",
                    published = "2023-01-01T00:00:00.000",
                    descriptions = {{lang = "en", value = long_description}},
                    metrics = {
                        cvssMetricV31 = {{
                            cvssData = {
                                baseScore = 7.5,
                                vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                            }
                        }}
                    }
                }
            }
        }
    }
    
    local vulns = format_vulnerability_info(mock_data, 0.0, 10)
    
    framework:assert_equal(#vulns, 1, "Should process vulnerability")
    framework:assert_true(#vulns[1].description <= 200, "Should truncate long descriptions")
    framework:assert_true(vulns[1].description:sub(-3) == "...", "Should add ellipsis to truncated descriptions")
end

-- Run all tests
local function main()
    local framework = TestFramework.new()
    
    -- Add test cases
    framework:add_test("test_build_cpe_from_port_with_complete_info", test_build_cpe_from_port_with_complete_info)
    framework:add_test("test_build_cpe_from_port_with_missing_vendor", test_build_cpe_from_port_with_missing_vendor)
    framework:add_test("test_build_cpe_from_port_no_version_info", test_build_cpe_from_port_no_version_info)
    framework:add_test("test_format_vulnerability_info_with_filtering", test_format_vulnerability_info_with_filtering)
    framework:add_test("test_format_vulnerability_info_max_limit", test_format_vulnerability_info_max_limit)
    framework:add_test("test_format_vulnerability_info_empty_data", test_format_vulnerability_info_empty_data)
    framework:add_test("test_format_vulnerability_info_long_description", test_format_vulnerability_info_long_description)
    
    -- Run tests
    local success = framework:run_tests()
    
    if success then
        print("\nAll tests passed! ✓")
        os.exit(0)
    else
        print("\nSome tests failed! ✗")
        os.exit(1)
    end
end

-- Enable debug output if requested
if arg and arg[1] == "--debug" then
    _G.DEBUG = true
end

main()