# iEdon PeerAPI Agent (Go)

Suite agent app runs on `iEdon-Net` nodes to collect, manage interfaces and peering sessions.

# Usage
Use as an agent utility on each node of your network.

```bash
Usage: ./peerapi-agent [-c config_file]
  -c string
        Path to the JSON configuration file (default "config.json")
  -h    Print this message
```

# Configuration
```json5
{
    "server": {
        "debug": false,
        "listen": ":8080",
        "readTimeout": 5, // Seconds
        "writeTimeout": 10, // Seconds
        "idleTimeout": 120, // Seconds
        "writeBufferSize": 4096, // Bytes
        "readBufferSize": 4096, // Bytes
        "bodyLimit": 1048576, // Bytes
        "trustedProxies": [
            "127.0.0.1",
            "::1"
        ]
    },

    "bird": {
        "controlSocket": "/var/run/bird/bird.ctl" // UNIX Domain Socket to interact with BIRD
    }

}
```

# Features
- ❌ Nothing, Under dev
