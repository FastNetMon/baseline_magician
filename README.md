# Introduction

This tool can create host group for each of your networks from networks_list with threhsolds generated using historical bandwidth usage from Clickhouse. More details: https://fastnetmon.com/docs-fnm-advanced/automatic-baseline-calculation-for-fastnetmon/

# Build process

```CGO_ENABLED=0 go build```

# Configuration

Create file /etc/fastnetmon/baseline_magician.conf and put following content into it:

```{
  "clickhouse_host": "127.0.0.1",
  "clickhouse_port": 9000, 
  "clickhouse_user": "admin",
  "clickhouse_password": "secure",
  "calculaton_period": 604800,
  "clickhouse_database": "fastnetmon",
  "clickhouse_table": "host_metrics",
  "api_user": "admin",
  "api_password": "XXX",
  "api_host": "127.0.0.1",
  "api_port": 10007,
  "generate_incoming_packet_threshold": true,
  "incoming_packet_expression": "value * 2",
  "generate_incoming_bit_threshold": true,
  "incoming_bit_expression": "value * 3",
  "generate_incoming_flow_threshold": true,
  "incoming_flow_expression": "value + 200",
  
  "remove_existing_hostgroups": true,
  "aggregation_function": "max"
}
```

All fields with expression suffix keep math expressions to calculate threshold/baseline value from aggregated value (using aggregation_function) of particular threshold from Clickhouse (calculated over last 7 days).

# Run

```
bin/baseline_magician
```

