# Fix USB energy settings on MTR devices

Fixes unhealthy USB Selective Suspend and USB Peripheral Power Drain status on Microsoft Teams Rooms devices.

Unhealthy USB settings can cause peripherals (cameras, speakerphones, USB hubs) to disconnect unexpectedly or behave unreliably during meetings:

- **USB Peripheral Power Drain** (`AttemptRecoveryFromUsbPowerDrain`) controls whether Windows attempts to recover USB devices that have lost power. Setting this to `0` disables the behaviour, preventing unintended USB resets.

- **USB Selective Suspend** allows Windows to put idle USB devices into a low-power state. On MTR devices this can cause peripherals to drop mid-call. Disabling it via powercfg ensures USB devices remain continuously powered on AC.


## References

- [The USB Peripheral Power Drain status of a Teams Rooms device is Unhealthy - Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/usb-peripheral-power-drain)
- [The USB Selective Suspend status of a Teams Rooms device is Unhealthy - Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/usb-selective-suspend)