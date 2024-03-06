# Release Notes

All notable changes to this project will be documented in this file.

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
