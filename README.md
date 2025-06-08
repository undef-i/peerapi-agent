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

## Graceful Shutdown

The peerapi-agent implements graceful shutdown handling to ensure that all background tasks are properly terminated and resources are cleaned up when the application shuts down. This helps prevent data loss and resource leaks.

When the application receives a shutdown signal (SIGINT, SIGTERM), it:

1. Cancels the root context to notify all background tasks to terminate
2. Gracefully shuts down the HTTP server
3. Waits for all background tasks to complete with a timeout
4. Performs final resource cleanup (database connections, BIRD pool, etc.)

The default shutdown timeout is 30 seconds, which should be sufficient for most deployments.

### Running as a Service

When running as a systemd service, the `peerapi-agent.service` file is configured with appropriate shutdown timeouts to ensure graceful termination.

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
