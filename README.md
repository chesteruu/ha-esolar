# ha-esolar

Home Assistant custom integration for **SAJ eSolar** solar inverters & battery storage systems.

Based on the original [`faanskit/ha-esolar`](https://github.com/faanskit/ha-esolar) integration, updated to work with SAJ's **v2 cloud API** (the legacy v1 endpoints have been retired).

## What changed

The upstream integration used the old `eop.saj-electric.com` **v1** API, which now returns dead endpoints (`/dev-api/api/v1/sys/login` no longer works). This fork migrates the API layer to **v2**:

- **Login**: `/dev-api/api/v2/sys/user/login` — JSON body with AES-128-ECB encrypted password.
- **Signing**: HMAC-SHA256 (`X-Sign`) over the canonicalized request metadata + body MD5, sent via `X-*` headers.
- **Realtime data**: `/dev-api/api/v2/monitor/device/getInverterEnergyDetail` + `/monitor/device/baseDeviceBatteryInfo`.
- **Plant metadata**: `/dev-api/api/v2/monitor/plant/userPlantPage` (resolves plant name / UID).

Entity structure (`sensor.py`, `__init__.py`) is unchanged, so existing dashboards keep working.

## Install

### HACS (custom repository)

1. HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/chesteruu/ha-esolar` as category **Integration**
3. Install **eSolar** and restart Home Assistant.

### Manual

Copy the `custom_components/saj_esolar_air` folder into your Home Assistant `config/custom_components/` directory and restart.

## Configuration

Add the integration from **Settings → Devices & Services → Add Integration → SAJ eSolar**, then enter:

- **Username** — your SAJ eSolar account email
- **Password** — your SAJ eSolar password
- **Device serial number** — your inverter's S/N

> Credentials are stored by Home Assistant in your own instance config; they are **not** part of this repository.

## Credits

- Original integration: [@faanskit](https://github.com/faanskit)
- v2 API migration: [@chesteruu](https://github.com/chesteruu)

## Disclaimer

Unofficial integration. Not affiliated with SAJ. Use at your own risk.
