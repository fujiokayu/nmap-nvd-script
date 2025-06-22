# Testing Guide for nvd-cve.nse

This document provides comprehensive instructions for setting up and running tests for the NVD CVE Nmap script.

## Quick Start

1. **Install dependencies**:
   ```bash
   # macOS
   brew install lua luarocks && luarocks install lua-cjson
   
   # Ubuntu/Debian
   sudo apt-get install lua5.3 liblua5.3-dev luarocks && luarocks install lua-cjson
   ```

2. **Run tests**:
   ```bash
   ./run_tests.sh
   ```

## Environment Setup

### Prerequisites

- **Lua interpreter** (version 5.3 or higher)
- **LuaRocks** package manager
- **lua-cjson** module for JSON handling
- **curl** (for real API tests only)
- **Internet connection** (for real API tests only)

### Platform-Specific Installation

#### macOS (Homebrew)
```bash
# Install Lua and LuaRocks
brew install lua luarocks

# Install JSON module
luarocks install lua-cjson

# Verify installation
lua -v
lua -e "require 'cjson'; print('✓ Environment ready')"
```

#### Ubuntu/Debian
```bash
# Update package index
sudo apt-get update

# Install Lua and development tools
sudo apt-get install lua5.3 liblua5.3-dev luarocks build-essential

# Install JSON module
luarocks install lua-cjson

# Verify installation
lua5.3 -v
lua5.3 -e "require 'cjson'; print('✓ Environment ready')"
```

#### CentOS/RHEL/Fedora
```bash
# Install Lua and development tools
sudo yum install lua lua-devel luarocks gcc

# Install JSON module
luarocks install lua-cjson

# Verify installation
lua -v
lua -e "require 'cjson'; print('✓ Environment ready')"
```

#### Alpine Linux
```bash
# Install Lua and development tools
apk add lua5.3 lua5.3-dev luarocks build-base

# Install JSON module
luarocks-5.3 install lua-cjson

# Verify installation
lua5.3 -v
lua5.3 -e "require 'cjson'; print('✓ Environment ready')"
```

### Manual Installation (if LuaRocks unavailable)

```bash
# Clone and build lua-cjson
git clone https://github.com/mpx/lua-cjson.git
cd lua-cjson

# Build (may need to adjust LUA_INCLUDE_DIR)
make LUA_INCLUDE_DIR=/usr/include/lua5.3

# Install
sudo make install

# Test
lua -e "require 'cjson'; print('✓ Manual installation successful')"
```

## Test Structure

### Test Types

1. **Unit Tests** (`tests/test_nvd_cve.lua`)
   - Test individual functions in isolation
   - Mock external dependencies
   - Validate core logic

2. **Integration Tests** (`tests/integration_test.lua`)
   - Test API integration with mock responses
   - Validate HTTP request handling
   - Test error scenarios

3. **Real API Tests** (`tests/real_api_test.lua`)
   - Test actual NVD CVE API 2.0 integration
   - Use known vulnerable software CPEs
   - Validate real vulnerability detection
   - Requires internet connection and curl

4. **Syntax Validation**
   - Basic Lua syntax checking
   - Nmap compatibility verification

### Test Coverage

| Component | Unit Tests | Integration Tests | Real API Tests |
|-----------|------------|-------------------|----------------|
| CPE Generation | ✓ | - | ✓ |
| Vendor Mapping | ✓ | - | ✓ |
| API Requests | - | ✓ | ✓ |
| Response Parsing | ✓ | ✓ | ✓ |
| Error Handling | ✓ | ✓ | ✓ |
| Filtering Logic | ✓ | - | ✓ |
| Rate Limiting | - | ✓ | ✓ |
| Vulnerability Detection | - | - | ✓ |

## Running Tests

### Basic Usage
```bash
# Run all tests
./run_tests.sh

# Get help
./run_tests.sh --help
```

### Test Options
```bash
# Run specific test types
./run_tests.sh --unit           # Unit tests only
./run_tests.sh --integration    # Integration tests only
./run_tests.sh --real-api       # Real API tests with known vulnerable CPEs
./run_tests.sh --syntax         # Syntax validation only

# Debug mode
./run_tests.sh --debug          # Enable verbose output
```

### Using Makefile
```bash
# All tests
make test

# Specific test types
make unit-test
make integration-test
make real-api-test             # Real API tests (requires curl and internet)
make syntax-check

# Debug mode
make test-debug

# Installation commands
make install                    # Install to nmap directory
make uninstall                 # Remove from nmap directory
```

## Test Output

### Successful Test Run
```
Starting test suite for nvd-cve.nse
====================================
Using: Lua 5.4.8  Copyright (C) 1994-2025 Lua.org, PUC-Rio
Checking Lua modules...
✓ JSON module available

=== Validating NSE Script Syntax ===
NSE script syntax check skipped (requires nmap modules)
This is normal - NSE scripts require nmap runtime environment

=== Running Unit Tests ===
Running tests...
================
✓ test_build_cpe_from_port_with_complete_info
✓ test_build_cpe_from_port_with_missing_vendor
✓ test_build_cpe_from_port_no_version_info
✓ test_format_vulnerability_info_with_filtering
✓ test_format_vulnerability_info_max_limit
✓ test_format_vulnerability_info_empty_data
✓ test_format_vulnerability_info_long_description
================
Tests: 7 passed, 0 failed, 7 total

=== Running Integration Tests ===
Running integration tests...
============================
✓ test_successful_api_response
✓ test_api_error_response
✓ test_invalid_json_response
✓ test_empty_vulnerabilities_response
✓ test_multiple_vulnerabilities_response
✓ test_api_with_api_key
============================
Integration tests: 6 passed, 0 failed, 6 total

=== Test Summary ===
All tests passed! ✓
The nvd-cve.nse script is ready for use.
```

## Troubleshooting

### Common Issues

#### "Lua is not installed"
```bash
# Install Lua for your platform
# macOS:
brew install lua

# Ubuntu/Debian:
sudo apt-get install lua5.3

# Verify:
lua -v
```

#### "lua-cjson module not found"
```bash
# Install via LuaRocks:
luarocks install lua-cjson

# If LuaRocks not available, install manually:
git clone https://github.com/mpx/lua-cjson.git
cd lua-cjson && make && sudo make install

# Verify:
lua -e "require 'cjson'"
```

#### "Permission denied" on test execution
```bash
# Make script executable:
chmod +x run_tests.sh

# Run tests:
./run_tests.sh
```

#### Different Lua versions
```bash
# Check available Lua versions:
ls /usr/bin/lua*

# Use specific version:
lua5.3 tests/test_nvd_cve.lua
```

### Debug Mode

Enable debug output for detailed test information:
```bash
./run_tests.sh --debug
```

This provides:
- Detailed test execution steps
- API request/response logging
- Error stack traces
- Module loading information

## Continuous Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install lua5.3 liblua5.3-dev luarocks
        luarocks install lua-cjson
    - name: Run tests
      run: ./run_tests.sh
```

### Docker Testing
```dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y \
    lua5.3 liblua5.3-dev luarocks build-essential
RUN luarocks install lua-cjson
COPY . /app
WORKDIR /app
RUN ./run_tests.sh
```

## Contributing

When adding new tests:

1. **Unit tests**: Add to `tests/test_nvd_cve.lua`
2. **Integration tests**: Add to `tests/integration_test.lua`
3. **Follow naming convention**: `test_function_name_scenario`
4. **Include assertions**: Use the test framework's assertion methods
5. **Test both success and failure cases**

Example test structure:
```lua
local function test_new_feature(framework)
    -- Setup
    local input = "test input"
    
    -- Execute
    local result = function_under_test(input)
    
    -- Assert
    framework:assert_equal(result, "expected output", "Should return expected result")
end
```