# NetWatch Core

Shared canonical schemas and utilities for NetWatch.

## Installation

```bash
pip install -e "D:\NetWatch\shared\netwatch_core[dev]"
```

## Schemas

- `shared.netwatch_core.schemas.flow_log.FlowLogEntry` - Canonical VPC Flow Log entry
- `shared.netwatch_core.schemas.flow_log.FlowLogEntryBatch` - Batch of flow log entries for API requests

## Usage

```python
from shared.netwatch_core.schemas.flow_log import FlowLogEntry, FlowLogEntryBatch

# Single entry
entry = FlowLogEntry(
    version=2,
    account_id="123456789012",
    interface_id="eni-0a1b2c3d4e5f6g7h8",
    src_addr="203.0.113.1",
    dst_addr="10.0.1.5",
    src_port=54321,
    dst_port=22,
    protocol=6,
    packets=10,
    bytes=600,
    start_time=1704067200,
    end_time=1704067260,
    action="ACCEPT",
    log_status="OK"
)

# Batch for API
batch = FlowLogEntryBatch(entries=[entry, ...])
```