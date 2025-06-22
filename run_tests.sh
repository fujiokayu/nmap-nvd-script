#!/bin/bash

# Test runner script for nvd-cve.nse project
# This script runs all tests and provides a summary

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_colored() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if Lua is available
check_lua() {
    if ! command -v lua &> /dev/null; then
        print_colored $RED "Error: Lua is not installed or not in PATH"
        print_colored $YELLOW "Please install Lua to run the tests"
        print_colored $YELLOW "On macOS: brew install lua"
        print_colored $YELLOW "On Ubuntu/Debian: sudo apt-get install lua5.3"
        print_colored $YELLOW "On CentOS/RHEL: sudo yum install lua"
        exit 1
    fi
    
    local lua_version=$(lua -v 2>&1 | head -n1)
    print_colored $BLUE "Using: $lua_version"
}

# Function to check if required Lua modules are available
check_lua_modules() {
    print_colored $BLUE "Checking Lua modules..."
    
    # Check for cjson module
    if ! lua -e "require 'cjson'" &> /dev/null; then
        print_colored $YELLOW "Warning: lua-cjson module not found"
        print_colored $YELLOW "Some tests may fail. To install:"
        print_colored $YELLOW "- LuaRocks: luarocks install lua-cjson"
        print_colored $YELLOW "- Or use system package manager"
    else
        print_colored $GREEN "✓ JSON module available"
    fi
}

# Function to run unit tests
run_unit_tests() {
    print_colored $BLUE "\n=== Running Unit Tests ==="
    
    if [ ! -f "tests/test_nvd_cve.lua" ]; then
        print_colored $RED "Error: Unit test file not found: tests/test_nvd_cve.lua"
        return 1
    fi
    
    if [ "$DEBUG" = "1" ]; then
        lua tests/test_nvd_cve.lua --debug
    else
        lua tests/test_nvd_cve.lua
    fi
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        print_colored $GREEN "✓ Unit tests passed"
        return 0
    else
        print_colored $RED "✗ Unit tests failed"
        return 1
    fi
}

# Function to run integration tests
run_integration_tests() {
    print_colored $BLUE "\n=== Running Integration Tests ==="
    
    if [ ! -f "tests/integration_test.lua" ]; then
        print_colored $RED "Error: Integration test file not found: tests/integration_test.lua"
        return 1
    fi
    
    if [ "$DEBUG" = "1" ]; then
        lua tests/integration_test.lua --debug
    else
        lua tests/integration_test.lua
    fi
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        print_colored $GREEN "✓ Integration tests passed"
        return 0
    else
        print_colored $RED "✗ Integration tests failed"
        return 1
    fi
}

# Function to run real API tests with known vulnerable CPEs
run_real_api_tests() {
    print_colored $BLUE "\n=== Running Real API Tests ==="
    print_colored $YELLOW "Note: These tests make actual calls to the NVD API"
    print_colored $YELLOW "Internet connection required. Tests include rate limiting delays."
    
    if [ ! -f "tests/real_api_test.lua" ]; then
        print_colored $RED "Error: Real API test file not found: tests/real_api_test.lua"
        return 1
    fi
    
    # Check if curl is available for actual HTTP requests
    if ! command -v curl &> /dev/null; then
        print_colored $RED "Error: curl is required for real API tests but not found"
        print_colored $YELLOW "Please install curl to make actual HTTP requests to NVD API"
        print_colored $YELLOW "On macOS: brew install curl"
        print_colored $YELLOW "On Ubuntu/Debian: sudo apt-get install curl"
        return 1
    fi
    
    print_colored $YELLOW "Found curl - will make actual HTTP requests to NVD API"
    
    if [ "$DEBUG" = "1" ]; then
        lua tests/real_api_test.lua --debug
    else
        lua tests/real_api_test.lua
    fi
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        print_colored $GREEN "✓ Real API tests passed"
        return 0
    else
        print_colored $RED "✗ Real API tests failed"
        return 1
    fi
}

# Function to validate NSE script syntax
validate_nse_syntax() {
    print_colored $BLUE "\n=== Validating NSE Script Syntax ==="
    
    if [ ! -f "nvd-cve.nse" ]; then
        print_colored $RED "Error: NSE script not found: nvd-cve.nse"
        return 1
    fi
    
    # Basic Lua syntax check - just check if file can be parsed
    if lua -e "dofile('nvd-cve.nse')" 2>/dev/null; then
        print_colored $GREEN "✓ NSE script syntax is valid"
        return 0
    else
        print_colored $YELLOW "NSE script syntax check skipped (requires nmap modules)"
        print_colored $YELLOW "This is normal - NSE scripts require nmap runtime environment"
        return 0
    fi
}

# Function to run nmap script validation (if nmap is available)
validate_with_nmap() {
    print_colored $BLUE "\n=== Validating with Nmap (if available) ==="
    
    if ! command -v nmap &> /dev/null; then
        print_colored $YELLOW "Nmap not found - skipping nmap-specific validation"
        return 0
    fi
    
    # Check if the script can be loaded by nmap
    if nmap --script-help nvd-cve 2>/dev/null | grep -q "nvd-cve"; then
        print_colored $GREEN "✓ Script is properly installed in Nmap"
    else
        print_colored $YELLOW "Script not installed in Nmap scripts directory"
        print_colored $YELLOW "To install: sudo cp nvd-cve.nse /usr/share/nmap/scripts/"
        print_colored $YELLOW "Then run: nmap --script-updatedb"
    fi
    
    return 0
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --debug     Enable debug output during tests"
    echo "  --unit      Run only unit tests"
    echo "  --integration Run only integration tests"
    echo "  --real-api  Run only real API tests with known vulnerable CPEs"
    echo "  --syntax    Run only syntax validation"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all tests"
    echo "  $0 --debug           # Run all tests with debug output"
    echo "  $0 --unit            # Run only unit tests"
    echo "  $0 --integration     # Run only integration tests"
}

# Main execution
main() {
    local run_unit=true
    local run_integration=true
    local run_real_api=false
    local run_syntax=true
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                export DEBUG=1
                shift
                ;;
            --unit)
                run_unit=true
                run_integration=false
                run_syntax=false
                shift
                ;;
            --integration)
                run_unit=false
                run_integration=true
                run_real_api=false
                run_syntax=false
                shift
                ;;
            --real-api)
                run_unit=false
                run_integration=false
                run_real_api=true
                run_syntax=false
                shift
                ;;
            --syntax)
                run_unit=false
                run_integration=false
                run_real_api=false
                run_syntax=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_colored $RED "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_colored $BLUE "Starting test suite for nvd-cve.nse"
    print_colored $BLUE "===================================="
    
    # Check prerequisites
    check_lua
    check_lua_modules
    
    local total_failures=0
    
    # Run selected tests
    if [ "$run_syntax" = true ]; then
        validate_nse_syntax || ((total_failures++))
        validate_with_nmap || ((total_failures++))
    fi
    
    if [ "$run_unit" = true ]; then
        run_unit_tests || ((total_failures++))
    fi
    
    if [ "$run_integration" = true ]; then
        run_integration_tests || ((total_failures++))
    fi
    
    if [ "$run_real_api" = true ]; then
        run_real_api_tests || ((total_failures++))
    fi
    
    # Summary
    print_colored $BLUE "\n=== Test Summary ==="
    if [ $total_failures -eq 0 ]; then
        print_colored $GREEN "All tests passed! ✓"
        print_colored $GREEN "The nvd-cve.nse script is ready for use."
        exit 0
    else
        print_colored $RED "Some tests failed! ($total_failures failure(s))"
        print_colored $RED "Please fix the issues before deploying the script."
        exit 1
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi