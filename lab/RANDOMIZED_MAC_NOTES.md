# Randomized MAC Address Detection

## What is a randomized MAC address?

A MAC address is used to identify a device on a network. Some devices, especially phones and laptops, use private or randomized MAC addresses instead of their manufacturer-assigned MAC address for privacy.

Because of this, Nmap may show the device's vendor as `Unknown`.

## How to detect one

According to the Watchtower PRD (T-04), we check the **locally administered bit** (the second least significant bit of the first byte of a MAC address).

In Python:

```python
int(mac.split(":")[0], 16) & 0b10 != 0
```

If the result is `True`, Watchtower treats the MAC as randomized/private.

## Example from our lab

The simulated laptop has this MAC address:

`3a:7f:21:9c:44:b1`

- First byte: `3a` (hexadecimal)
- Binary: `00111010`
- The locally administered bit is set.
- Therefore, Watchtower should mark `mac_randomised = True`.

For these addresses, the PRD specifies the vendor label:

`Private address (randomised MAC)`

**Note:** The locally administered bit indicates that the address is locally assigned, not necessarily that it was randomly generated. Watchtower uses this bit for its private-address classification.