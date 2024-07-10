# Release Notes

All notable changes to this project will be documented in this file.

## Version 0.11.1

- Stability bugfixes

## Version 0.11.0

- Use modern crates anyhow and thiserror instead of failure

## Version 0.10.29

- Refactor TL vector interface

## Version 0.10.28

- Update dependencies

## Version 0.10.27

- Configure broadcast parameters

## Version 0.10.19

- Supported merge of block and types repos

## Version 0.10.18

- Update of dependencies

## Version 0.10.5

- Merge DHT repo into ADNL repo (see DHT changelog in the end of this file)

## Version 0.10.4

- Merge Overlay repo into ADNL repo (see Overlay changelog in the end of this file)

## Version 0.10.3

- Merge RLDP repo into ADNL repo (see RLDP changelog in the end of this file)

## Version 0.10.1

- Get rid of ton::bytes type

## Version 0.10.0

- Prepare to make united crate for protocols

## Version 0.9.17

- Remove duplicated telemetry

## Version 0.9.9

- Performance improvements

## Version 0.9.0

- ADNL channel reset on

## Version 0.8.31

- Introduce server ID

## Version 0.8.21

- Use `thread_rng().fill` to fill buffer in  `AdnlClient::send_init_packet`

## Version 0.8.20

- `AdnlClient::send_init_packet` is thread safe and can be spawned

## Version 0.8.19

- Fix compiler warnings
- Increase package version

## Version 0.8.18

- Turn off ADNL channel reset feature to provide seamless update

## Version 0.8.15

- Do not use base64, crypto crates directly

## Version 0.8.1

- Introduce ADNL connection status

## Version 0.8.0

- Push peer to refresh after channel reset

## Version 0.7.180

- Add adjusted interface to Wait
- Increase package version

## Version 0.7.166

- Get rid of workspace
- Increase package version

## Version: 0.7.144

### New

- Improved monitoring of ADNL channels

## Version: 0.7.75

### New

- Bump zstd version up (0.11)

# RLDP protocol Release Notes Archive

## Version 0.8.22

- Prepare to make united crate for protocols

## Version 0.8.20

- Rebranding ton -> everx
- Get rid of ton::bytes type

## Version 0.8.0

- Ignore expired RLDP queries
- Async processing of queries

## Version 0.7.212

- Update raptorQ crate to 1.7.0

## Version 0.7.210

- Refactor RLDP message sanity check

## Version 0.7.209

- Added RLDP message sanity check

## Version 0.7.200

- Do not use base64 and crypto crates directly

## Version 0.7.184

- Use externally managed port

## Version 0.7.140

- Supported ever-types version 2.0

# Overlay protocol Release Notes Archive

## Version 0.7.26

- Code clean up 

## Version 0.7.25

- Rebranding ton -> everx

## Version 0.7.24

- Prepare to make united crate for protocols

## Version 0.7.17

- Added flag started_listening to fix queue overflow

## Version 0.7.2

- Async processing of queries

## Version 0.7.0

- Support BLS-related broadcasts

## Version 0.6.236

- Transparently support hops check for old-fashioned broadcasts

## Version 0.6.217

- Overlay message sanity check

## Version: 0.6.213

- Allow to send duplicated broadcasts

## Version: 0.6.205

- Do not use base64, crypto crates directly

## Version 0.6.187

- Use externally managed port

## Version 0.6.181

- Yet more stabilize verification

## Version 0.6.180

- Use network config for evaluation
- Support fast DHT policy

## Version: 0.6.93

- Added export build commit of library

## Version: 0.6.62

- Added control for # of hops in broadcast

# DHT protocol Release Notes Archive

## Version 0.7.3

- Prepare to make united crate for protocols

## Version 0.7.2

- Rebranding ton -> everx

## Version 0.7.0

- Multi-network DHT

## Version 0.6.56

- Support hops check for old-fashioned broadcasts

## Version 0.6.25

- Remove ever-crypto crate

## Version 0.6.20

- Small fixes for pipeline

## Version 0.6.5

- Use externally configured port

## Version 0.6.0

- Adapt to rare cases when DHT network may fail fast query at first time
- Increase package version

## Version 0.5.202

- DHT performance optimization
- Overlay node search with iterations
- Increase package version greatly
- Fix build due to broken dependencies
- Adjust some comments
- Support for different DHT search policies

## Version 0.5.187

- Use global config to verify on mainnet
- Increase package version

## Version 0.5.186

- Limit maximum score of bad peer
- Increase package version

## Version 0.5.177

- Get rid of workspace
- Increase package version

## Version: 0.5.72

### New

- Changed API for DHT overlay node address search

## Version: 0.5.70

### New

- Construction of DHT node info with arbitrary timestamp
