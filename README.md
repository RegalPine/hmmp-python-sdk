# HMMP Python SDK

Python client SDK for the **High-Performance Microservice Multiplex Protocol (HMMP) v07**.

## Features

- Full HMMP v07 protocol implementation
- Service registration and discovery
- Configuration management with caching and canary release support
- End-to-end encryption and authentication
- Circuit breaker, backpressure, and adaptive load balancing
- Governance block parsing and traffic coloring
- Frame interceptor chain

## Requirements

- Python >= 3.10
- msgpack >= 1.0.0
- cryptography >= 41.0.0

## Installation

```bash
pip install hmmp-python
```

## Quick Start

```python
import asyncio
from hmmp import HMMPClient, ClientConfig, ServiceInstance

async def main():
    config = ClientConfig(
        host="127.0.0.1",
        port=8848,
        access_key="my-app",
        secret_key="my-secret",
    )

    async with HMMPClient(config) as client:
        # Register a service instance
        instance = ServiceInstance(
            service_name="user-service",
            ip="192.168.1.100",
            port=8080,
            weight=1.0,
        )
        await client.register_instance(instance)

        # Discover services
        snapshot = await client.discover_service("user-service")
        for inst in snapshot.instances:
            print(f"Found: {inst.ip}:{inst.port}")

        # Get configuration
        entry = await client.get_config("app.yaml", group="DEFAULT_GROUP")
        print(entry.content_str)

asyncio.run(main())
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).
