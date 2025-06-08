# iEdon PeerAPI Agent

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-blue.svg)](https://golang.org)

A comprehensive agent for managing BGP peering sessions on `iEdon-Net` nodes. This agent connects to a central PeerAPI server for coordination and management of BGP sessions, automated configuration, network monitoring, and metric collection.

## Features

- **BGP Session Management**
  - Automated setup and teardown of BGP peering sessions
  - Support for traditional BGP and MP-BGP configurations
  - Dynamic interface configuration (WireGuard, GRE, IP addressing)
  - Session status monitoring and reporting

- **BIRD Integration**
  - Real-time configuration generation and updating
  - Connection pooling for efficient BIRD control
  - Route statistics collection
  - Support for BGP communities and advanced filtering

- **Performance Monitoring**
  - RTT (Round Trip Time) measurement for all peering sessions
  - Bandwidth usage monitoring for network interfaces
  - Node resource metrics (CPU, memory, connections)

- **DN42 BGP Communities Support**
  - Automatic latency-based community assignment (64511, X)
  - Dynamic community updates based on real-time RTT measurements 
  - Bandwidth and security community propagation

- **Geographic Awareness**
  - GeoIP-based session validation
  - Region-specific routing policies
  - Geographic metrics for peering sessions

- **Robust Infrastructure**
  - Graceful shutdown for clean termination
  - Concurrent background tasks with proper synchronization
  - Resource cleanup and leak prevention

- **Security**
  - JWT-based authentication with the central PeerAPI server
  - Session validation and verification

## Installation

### Prerequisites

- Go 1.21 or higher
- BIRD routing daemon 2.0 or higher
- MaxMind GeoLite2 Country database (optional, for geo features)
- Root/administrative privileges (for network interface management)

### Binary Installation

1. Download the latest release:

```bash
curl -L -o peerapi-agent https://github.com/iedon/peerapi-agent/releases/latest/download/peerapi-agent-linux-amd64
chmod +x peerapi-agent
```

2. Create a configuration file (see Configuration section)

3. Run the agent:

```bash
./peerapi-agent -c config.json
```

### Building from Source

```bash
git clone https://github.com/iedon/peerapi-agent.git
cd peerapi-agent/src
go build -o peerapi-agent
```

### Running as a Service

A systemd service file is included in the repository. To install:

1. Copy the binary to your preferred location:

```bash
cp peerapi-agent /data/peerapi-agent/
```

2. Copy the service file:

```bash
cp peerapi-agent.service /etc/systemd/system/
```

3. Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable peerapi-agent
systemctl start peerapi-agent
```

## Usage

```bash
Usage: ./peerapi-agent [-c config_file]
  -c string
        Path to the JSON configuration file (default "config.json")
  -h    Print this message
```

## Graceful Shutdown

The peerapi-agent implements graceful shutdown handling to ensure that all background tasks are properly terminated and resources are cleaned up when the application shuts down. This helps prevent data loss and resource leaks.

When the application receives a shutdown signal (SIGINT, SIGTERM), it:

1. Cancels the root context to notify all background tasks to terminate
2. Gracefully shuts down the HTTP server
3. Waits for all background tasks to complete with a timeout
4. Performs final resource cleanup (database connections, BIRD pool, etc.)

The default shutdown timeout is 30 seconds, which should be sufficient for most deployments.

## Configuration

Configuration is stored in a JSON file. Below is an example with explanations:

```json
{
    "server": {
        "debug": false,
        "listen": ":8080",
        "readTimeout": 5,
        "writeTimeout": 10,
        "idleTimeout": 120,
        "writeBufferSize": 4096,
        "readBufferSize": 4096,
        "bodyLimit": 1048576,
        "trustedProxies": ["127.0.0.1", "::1"]
    },
    
    "peerApiCenter": {
        "url": "https://peerapi.example.org",
        "secret": "shared-secret",
        "requestTimeout": 15,
        "routerUuid": "00000000-0000-0000-0000-000000000000",
        "agentSecret": "your-agent-secret-key",
        "heartbeatInterval": 30,
        "syncInterval": 300,
        "metricInterval": 60,
        "wanInterfaces": ["eth0"],
        "sessionPassthroughJwtSecert": "jwt-secret-for-node-passthrough"
    },
    
    "bird": {
        "controlSocket": "/var/run/bird/bird.ctl",
        "poolSize": 5,
        "poolSizeMax": 128,
        "bgpPeerConfDir": "/etc/bird/peers",
        "bgpPeerConfTemplateFile": "./templates/peer.conf"
    },
    
    "metric": {
        "autoTeardown": true,
        "maxMindGeoLiteCountryMmdbPath": "./GeoLite2-Country.mmdb",
        "geoIPCountryMode": "blacklist",
        "blacklistGeoCountries": ["CN"],
        "whitelistGeoCountries": ["US", "DE", "FR", "GB", "NL", "JP", "CA", "AU"],
        "pingTimeout": 5,
        "pingCount": 4
    },

    "wireguard": {
        "ipv4": "172.23.91.132",
        "ipv6": "fd42:4242:2189:118::1",
        "ipv6LinkLocal": "fe80::118",
        "privateKeyPath": "/etc/wireguard/privateKey",
        "publicKeyPath": "/etc/wireguard/publicKey",
        "persistentKeepaliveInterval": 25,
        "localEndpointHost": "example.dn42.net",
        "dn42BandwidthCommunity": 24,
        "dn42InterfaceSecurityCommunity": 34
    },

    "gre": {
        "ipv4": "172.23.91.132",
        "ipv6": "fd42:4242:2189:118::1",
        "ipv6LinkLocal": "fe80::118",
        "localEndpointHost4": "203.0.113.1",
        "localEndpointHost6": "2001:db8::1",
        "dn42BandwidthCommunity": 24,
        "dn42InterfaceSecurityCommunity": 31
    }
}
```

### Server Configuration

| Parameter | Description |
|-----------|-------------|
| `debug` | Enable debug mode |
| `listen` | Address and port to listen on |
| `readTimeout` | Read timeout in seconds |
| `writeTimeout` | Write timeout in seconds |
| `idleTimeout` | Idle timeout in seconds |
| `writeBufferSize` | Write buffer size in bytes |
| `readBufferSize` | Read buffer size in bytes |
| `bodyLimit` | Maximum request body size in bytes |
| `trustedProxies` | List of trusted proxy IP addresses |

### PeerApiCenter Configuration

| Parameter | Description |
|-----------|-------------|
| `url` | URL of the central PeerAPI server |
| `secret` | Shared secret for authentication with PeerAPI center |
| `requestTimeout` | API request timeout in seconds |
| `routerUuid` | UUID of this router from PeerAPI server |
| `agentSecret` | Secret key for agent authentication |
| `heartbeatInterval` | Heartbeat interval in seconds |
| `syncInterval` | Session sync interval in seconds (how often to sync with central server) |
| `metricInterval` | Metric collection interval in seconds |
| `wanInterfaces` | List of WAN interfaces to monitor for traffic statistics |
| `sessionPassthroughJwtSecert` | JWT secret for session passthrough authentication |

### Bird Configuration

| Parameter | Description |
|-----------|-------------|
| `controlSocket` | Path to BIRD control socket |
| `poolSize` | Initial BIRD connection pool size |
| `poolSizeMax` | Maximum BIRD connection pool size |
| `bgpPeerConfDir` | Directory for BGP peer configuration files |
| `bgpPeerConfTemplateFile` | Template file for BGP peer configuration |

### Metric Configuration

| Parameter | Description |
|-----------|-------------|
| `autoTeardown` | Whether to automatically tear down problematic sessions |
| `maxMindGeoLiteCountryMmdbPath` | Path to MaxMind GeoIP database |
| `geoIPCountryMode` | GeoIP filtering mode ("blacklist" or "whitelist") |
| `blacklistGeoCountries` | Array of country codes to block when in blacklist mode |
| `whitelistGeoCountries` | Array of country codes to allow when in whitelist mode |
| `pingTimeout` | Timeout in seconds for ping operations |
| `pingCount` | Number of pings to send for RTT measurement |

### WireGuard Configuration

| Parameter | Description |
|-----------|-------------|
| `ipv4` | IPv4 address for WireGuard interfaces |
| `ipv6` | IPv6 address for WireGuard interfaces |
| `ipv6LinkLocal` | IPv6 link-local address |
| `privateKeyPath` | Path to WireGuard private key |
| `publicKeyPath` | Path to WireGuard public key |
| `persistentKeepaliveInterval` | Interval in seconds for WireGuard keepalive |
| `localEndpointHost` | Hostname of local endpoint for WireGuard |
| `dn42BandwidthCommunity` | BGP community value indicating bandwidth capacity |
| `dn42InterfaceSecurityCommunity` | BGP community value indicating security level |

### GRE Configuration

| Parameter | Description |
|-----------|-------------|
| `ipv4` | IPv4 address for GRE tunnel interfaces |
| `ipv6` | IPv6 address for GRE tunnel interfaces |
| `ipv6LinkLocal` | IPv6 link-local address |
| `localEndpointHost4` | IPv4 address of local endpoint for GRE tunnels |
| `localEndpointHost6` | IPv6 address of local endpoint for GRE tunnels |
| `dn42BandwidthCommunity` | BGP community value indicating bandwidth capacity |
| `dn42InterfaceSecurityCommunity` | BGP community value indicating security level |

## Architecture

The peerapi-agent consists of several background tasks that run concurrently:

1. **Heartbeat Task**: Sends periodic health information to the central PeerAPI server
2. **Session Sync Task**: Synchronizes BGP session configurations with the central server
3. **Metric Task**: Collects and reports performance metrics for all sessions
4. **Bandwidth Monitor Task**: Monitors network interface traffic rates
5. **DN42 BGP Community Task**: Updates BGP communities based on performance metrics
6. **GeoCheck Task**: Validates sessions based on geographic data

These tasks communicate through shared data structures protected by mutexes to ensure thread safety.

## Development

### Project Structure

```
peerapi-agent/
├── src/
│   ├── auth.go           # Authentication functions
│   ├── bird/             # BIRD routing daemon integration
│   │   ├── bird.go       # BIRD control interface
│   │   └── conn.go       # Connection handling
│   ├── config.go         # Configuration loading and validation
│   ├── functions.go      # Utility functions
│   ├── handler.go        # HTTP request handlers
│   ├── main.go           # Application entry point
│   ├── session.go        # BGP session management
│   ├── task_*.go         # Background tasks
│   └── types.go          # Data structure definitions
├── templates/
│   └── bird_peer.conf    # BIRD configuration template
└── peerapi-agent.service # Systemd service file
```

## Frameworks / Suites used

- [BIRD](https://bird.network.cz/) - The BIRD Internet Routing Daemon
- [MaxMind](https://www.maxmind.com/) - For GeoLite2 databases
- [Fiber](https://gofiber.io/) - Fast HTTP framework
