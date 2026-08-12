# Hardware & Wiring

## Status: TBD pending real parts

The owner specified the board (**ESP32-S3**) but not the exact
temperature sensor or relay module. Everything below is a **reasonable
default assumption**, not a confirmed BOM — swap it out once real parts
are chosen, and update `CONFIG_WESPE_DS18B20_GPIO`/`CONFIG_WESPE_RELAY_GPIO`
(`firmware/main/Kconfig.projbuild`) accordingly. Nothing above the `device_hal/`
layer needs to change either way (see `docs/architecture.md`).

Until then, build with `CONFIG_WESPE_HAL_MOCK=y` (menuconfig: *Wespe SNMP
Agent Configuration → Use mock sensor/relay*) to exercise the whole SNMP
agent — including `wespeTemperature` and `wespeRelayState` — on a bare
ESP32-S3 dev board with nothing wired up at all. `device_hal/sensor_mock.c`
returns a fixed 23.5°C; `device_hal/relay_mock.c` just remembers the commanded
state in RAM.

## Assumed parts

| Part | Assumption | Why |
|---|---|---|
| Board | Generic ESP32-S3 DevKitC-style module | Matches the owner's stated target; plenty of GPIO, USB-serial built in |
| Temperature sensor | DS18B20, 1-Wire | Extremely common, cheap, well-documented, single-GPIO interface |
| Relay | Single-channel 5V relay module (opto-isolated input recommended) | Standard hobbyist part; opto-isolation protects the ESP32-S3's GPIO from the relay coil's switching noise |

## Wiring (default Kconfig GPIOs)

```
ESP32-S3                              DS18B20
┌─────────────┐                      ┌──────────┐
│         3V3 ├──────────┬───────────┤ VDD      │
│             │        4.7kΩ         │          │
│      GPIO4  ├──────────┴───────────┤ DQ       │
│             │                      │          │
│         GND ├──────────────────────┤ GND      │
└─────────────┘                      └──────────┘
                                      (4.7kΩ pull-up between DQ and 3V3
                                       is required by the 1-Wire spec;
                                       some breakout boards include it)

ESP32-S3                              Relay module
┌─────────────┐                      ┌──────────┐
│      GPIO5  ├──────────────────────┤ IN       │
│         5V  ├──────────────────────┤ VCC      │   (or 3V3, check your
│         GND ├──────────────────────┤ GND      │    module's logic level)
└─────────────┘                      └──────────┘
```

`GPIO_MODE_INPUT_OUTPUT_OD` (open-drain) + internal pull-up is enabled in
software for the DS18B20 line (`sensor_ds18b20.c`) as a fallback, but an
external 4.7kΩ resistor is still recommended per the DS18B20 datasheet,
especially over any wire length.

**Active-high assumed for the relay.** If your module is active-low
(common on cheap modules — `IN` pulled low energizes the relay), flip the
`gpio_set_level()` calls in `relay_gpio.c`.

## Bring-up sequence

1. Flash with `CONFIG_WESPE_HAL_MOCK=y` first — confirms WiFi, the SNMP
   agent, and MIB-II/WESPE-MIB objects all work before any soldering.
2. Wire the DS18B20, rebuild with `CONFIG_WESPE_HAL_MOCK=n`, confirm
   `wespeTemperature` tracks a real temperature change (e.g. holding the
   sensor).
3. Wire the relay, confirm `snmpset ... wespeRelayState.0 i 1` audibly
   clicks it and `wespeRelayState.0` reads back `1`.

See [`testing.md`](testing.md) for the exact `snmpget`/`snmpwalk`/`snmpset`
commands (demonstrated there against the host-native `dev_agent`, since no
physical ESP32-S3 was available in the environment this was built in —
the commands themselves are identical against real hardware, just with
the board's DHCP-assigned IP and port 161 instead of `127.0.0.1:1161`).
