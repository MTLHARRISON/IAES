# Intune Automated Enrollement Script

This script is a tweaked version of the Get-WindowsAutopilotInfo Script
https://www.powershellgallery.com/packages/Get-WindowsAutoPilotInfo/3.8

## Tweaks Include
- Installation of DPI (Deep Packet Inspection) Certificate
- Client Secret Expiry Checks
- Check for Active Internet Connection

## Installtion

- Create and Entra Appliction Registration.
- Under API permissions set the following ( Microsoft Graph / Application Permissions )
    - Device.ReadWrite.All
    - DeviceManagementManagedDevices.ReadWrite.All
    - DeviceManagementServiceConfig.ReadWrite.All
    - Group.ReadWrite.All
    - GroupMember.ReadWrite.All

- In the Script set the following variables:
    - $TenantId = Directory (tenant) ID
    - $AppId = Application (client) ID
    - $AppSecret = Secret Value
    - $AddToGroup = The Group Name your Autopilot Profile is applied to
    - $expiry_date = Expires Colulm of the Secret from $AppSecret
    - $ca_url = A webserver that has a copy of the CA for DPI / Content Filter
    - $Assign = If you want the script to pause until the profile is assinged set this to $true
    - $Reboot = Reboot at the end of the script



## Usage

### USB Deployment (Single Device)
Load the HardwareHash.ps1 onto a USB stick 
In Windows OOBE (Out of Box Expirence) press shift+F10 to open cmd
type powershell to switch to a powershell command window
modify the execution policy by typing:
>Set-ExecutionPolicy Unrestricted -Scope Process

cd to your USB usually D: or E:
Run .\HardwareHash.ps1

## MDT / SCCM (Mass Deployment)

Add this script to a Task Sequence to collect the hardware and hash.
Make sure you add a step to Enter OOBE after the script has ran.


