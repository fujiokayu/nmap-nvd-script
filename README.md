# Nmap NVD Script

An Nmap NSE (Nmap Scripting Engine) script that queries the NVD (National Vulnerability Database) CVE API 2.0 to find known vulnerabilities for services and software detected during version scanning.

## Features

- Automatically generates CPE (Common Platform Enumeration) identifiers from Nmap version detection results
- Queries the official NVD CVE API 2.0 for vulnerability information
- Filters results by CVSS score threshold
- Supports NVD API keys for higher rate limits
- Removes duplicate CVEs and limits output for readability
- Sorts results by CVSS score (highest first)

## Requirements

- Nmap with NSE support
- Internet connection to access NVD API
- Nmap version detection (`-sV` flag) to generate CPE identifiers

## Installation

1. Copy `nvd-cve.nse` to your Nmap scripts directory:
   ```bash
   # Find your scripts directory
   nmap --script-help | grep "script-help"
   
   # Copy the script (example paths)
   sudo cp nvd-cve.nse /usr/share/nmap/scripts/
   # or on macOS with Homebrew
   cp nvd-cve.nse /opt/homebrew/share/nmap/scripts/
   ```

2. Update the script database:
   ```bash
   nmap --script-updatedb
   ```

## Usage

### Basic Usage
```bash
# Scan with version detection and vulnerability lookup
nmap -sV --script nvd-cve <target>
```

### Advanced Usage
```bash
# Filter by minimum CVSS score
nmap -sV --script nvd-cve --script-args mincvss=7.0 <target>

# Use API key for higher rate limits
nmap -sV --script nvd-cve --script-args apikey=<your-api-key> <target>

# Combine multiple options
nmap -sV --script nvd-cve --script-args mincvss=5.0,apikey=<key>,maxcves=5 <target>
```

## Script Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `mincvss` | 0.0 | Minimum CVSS score threshold for filtering results |
| `apikey` | None | NVD API key for higher rate limits (optional) |
| `timeout` | 10 | HTTP request timeout in seconds |
| `maxcves` | 10 | Maximum number of CVEs to display per service |

## API Key

To avoid rate limiting (6-second delays), obtain a free API key:

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Request an API key
3. Use it with the script: `--script-args apikey=<your-key>`

With an API key, the minimum delay between requests is reduced to 0.6 seconds.

## Example Output

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| nvd-cve: 
| Found 3 vulnerabilities (showing 3, total in NVD: 8)
|   CVE-2018-15473 (CVSS: 5.3) OpenSSH through 7.7 is prone to a user enumeration vulnerability...
|   CVE-2016-10708 (CVSS: 5.0) sshd in OpenSSH before 7.4 allows remote attackers to cause...
|   CVE-2017-15906 (CVSS: 5.0) The process_open function in sftp-server.c in OpenSSH before 7.6...
| 
| Queried CPEs:
|   cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*
|_  cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*
```

## Rate Limiting

- **Without API key**: 6-second delay between requests
- **With API key**: 0.6-second minimum delay between requests

The script automatically handles rate limiting to comply with NVD API requirements.

## Limitations

- Requires `-sV` flag for version detection to generate CPE identifiers
- Subject to NVD API rate limits
- CPE generation may not be perfect for all software
- Limited to vulnerabilities available in the NVD database

## Testing

The project includes comprehensive tests to ensure reliability and correctness.

### Running Tests

```bash
# Run all tests
./run_tests.sh

# Run tests with debug output
./run_tests.sh --debug

# Run only unit tests
./run_tests.sh --unit

# Run only integration tests
./run_tests.sh --integration

# Run real API tests with known vulnerable CPEs
./run_tests.sh --real-api

# Run only syntax validation
./run_tests.sh --syntax
```

### Using Make

```bash
# Run all tests
make test

# Run specific test types
make unit-test
make integration-test
make real-api-test             # Requires curl and internet connection
make syntax-check

# Run tests with debug output
make test-debug

# Install script to nmap directory
make install

# Remove script from nmap directory
make uninstall
```

### Test Structure

- **Unit Tests** (`tests/test_nvd_cve.lua`): Test individual functions like CPE generation and vulnerability filtering
- **Integration Tests** (`tests/integration_test.lua`): Test API integration with mock responses
- **Syntax Validation**: Verify Lua syntax and nmap compatibility

### Test Requirements

- Lua interpreter
- lua-cjson module (required for JSON parsing in tests)

### Setting Up Test Environment

#### macOS (using Homebrew)
```bash
# Install Lua and LuaRocks
brew install lua luarocks

# Install required JSON module
luarocks install lua-cjson
```

#### Ubuntu/Debian
```bash
# Install Lua and development tools
sudo apt-get update
sudo apt-get install lua5.3 liblua5.3-dev luarocks

# Install required JSON module
luarocks install lua-cjson
```

#### CentOS/RHEL/Fedora
```bash
# Install Lua and development tools
sudo yum install lua lua-devel luarocks

# Install required JSON module
luarocks install lua-cjson
```

#### Manual Installation
If LuaRocks is not available:
```bash
# Download and compile lua-cjson from source
git clone https://github.com/mpx/lua-cjson.git
cd lua-cjson
make
sudo make install
```

### Verifying Test Environment
```bash
# Check Lua installation
lua -v

# Verify JSON module
lua -e "require 'cjson'; print('JSON module OK')"

# Run test verification
./run_tests.sh --help
```

## Development

See `CLAUDE.md` for development guidelines and architecture documentation.

## License

Same as Nmap - See https://nmap.org/book/man-legal.html