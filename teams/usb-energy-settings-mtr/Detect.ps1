#=============================================================================================================================
#
# Script Name:         Detect.ps1
# Description:         Detect if USB Selective Suspend and USB Peripheral Power Drain are configured correctly
#
#=============================================================================================================================

try {

    # Check USB Selective Suspend AC power setting
    $output = powercfg /QUERY SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
    $acLine = $output | Select-String "Current AC Power Setting Index"
    $acValue = ($acLine -replace ".*:\s*", "").Trim()

    if ($acValue -ne "0x00000000") {
        Write-Host "USB Selective Suspend is enabled on AC (value: $acValue)."
        exit 1
    }

    # Check USB Peripheral Power Drain registry key
    $registryUSB = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval" -ErrorAction SilentlyContinue

    if ($null -eq $registryUSB) {
        Write-Host "USB Peripheral Power Drain registry key not found."
        exit 1
    }

    if ($registryUSB.AttemptRecoveryFromUsbPowerDrain -ne 0) {
        Write-Host "USB Peripheral Power Drain is set to: $($registryUSB.AttemptRecoveryFromUsbPowerDrain)."
        exit 1
    }

    # All settings configured correctly
    Write-Host "USB Selective Suspend (AC) is disabled and USB Peripheral Power Drain status set to 0. OK."
    exit 0

} catch {
    $errMsg = $_.Exception.Message
    Write-Host "Error: $errMsg"
    exit 1
}