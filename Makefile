# Makefile for nvd-cve.nse project

.PHONY: test unit-test integration-test real-api-test install clean help syntax-check

# Default target
all: test

# Run all tests
test:
	@echo "Running all tests..."
	@./run_tests.sh

# Run only unit tests
unit-test:
	@echo "Running unit tests..."
	@./run_tests.sh --unit

# Run only integration tests
integration-test:
	@echo "Running integration tests..."
	@./run_tests.sh --integration

# Run real API tests with known vulnerable CPEs
real-api-test:
	@echo "Running real API tests (requires internet connection)..."
	@lua tests/real_api_test.lua

# Run syntax validation
syntax-check:
	@echo "Running syntax check..."
	@./run_tests.sh --syntax

# Run tests with debug output
test-debug:
	@echo "Running tests with debug output..."
	@./run_tests.sh --debug

# Install script to nmap scripts directory
install:
	@echo "Installing nvd-cve.nse to nmap scripts directory..."
	@if [ -d "/usr/share/nmap/scripts" ]; then \
		sudo cp nvd-cve.nse /usr/share/nmap/scripts/; \
		sudo nmap --script-updatedb; \
		echo "Script installed successfully"; \
	elif [ -d "/opt/homebrew/share/nmap/scripts" ]; then \
		cp nvd-cve.nse /opt/homebrew/share/nmap/scripts/; \
		nmap --script-updatedb; \
		echo "Script installed successfully (Homebrew)"; \
	else \
		echo "Error: Could not find nmap scripts directory"; \
		echo "Please install manually or specify the correct path"; \
		exit 1; \
	fi

# Uninstall script from nmap scripts directory
uninstall:
	@echo "Removing nvd-cve.nse from nmap scripts directory..."
	@if [ -f "/usr/share/nmap/scripts/nvd-cve.nse" ]; then \
		sudo rm /usr/share/nmap/scripts/nvd-cve.nse; \
		sudo nmap --script-updatedb; \
		echo "Script removed successfully"; \
	elif [ -f "/opt/homebrew/share/nmap/scripts/nvd-cve.nse" ]; then \
		rm /opt/homebrew/share/nmap/scripts/nvd-cve.nse; \
		nmap --script-updatedb; \
		echo "Script removed successfully (Homebrew)"; \
	else \
		echo "Script not found in nmap scripts directory"; \
	fi

# Clean up temporary files
clean:
	@echo "Cleaning up..."
	@find . -name "*.tmp" -delete
	@find . -name "*.log" -delete
	@echo "Clean complete"

# Show help
help:
	@echo "Available targets:"
	@echo "  test            - Run all tests"
	@echo "  unit-test       - Run unit tests only"
	@echo "  integration-test - Run integration tests only"
	@echo "  real-api-test   - Run real API tests with known vulnerable CPEs"
	@echo "  syntax-check    - Run syntax validation only"
	@echo "  test-debug      - Run tests with debug output"
	@echo "  install         - Install script to nmap scripts directory"
	@echo "  uninstall       - Remove script from nmap scripts directory"
	@echo "  clean           - Clean up temporary files"
	@echo "  help            - Show this help message"