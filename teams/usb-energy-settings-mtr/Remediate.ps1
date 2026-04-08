#=============================================================================================================================
#
# Script Name:         Remediate.ps1
# Description:         Remediate USB Selective Suspend and USB Peripheral Power Drain
#
#=============================================================================================================================

try {
    # Set USB Peripheral Power Drain to 0
    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval" -Name "AttemptRecoveryFromUsbPowerDrain" -Value 0 -Type DWord

    # Disable USB Selective Suspend on AC power
    powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

    exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Host "Error: $errMsg"
    exit 1
}