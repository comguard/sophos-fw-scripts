## fwrulesToexcel.py

Script connects to Sophos XG/XGs firewall through API, and export firewall rules to Excel document.

### Exported fields

```
- Group
- Name
- Description
- Status
- Action
- LogTraffic
- SourceZones
- SourceNetworks
- DestinationZones
- DestinationNetworks
- Services
- WebFilter
- ApplicationControl
```

## natrulesToexcel.py

Script connects to Sophos XG/XGs firewall through API, and export NAT rules to Excel document.

### Exported fields

```
- Name
- Description
- IPFamily
- Status
- Position
- LinkedFirewallrule
- TranslatedDestination
- TranslatedService
- OutboundInterfaces
- OverrideInterfaceNATPolicy
- TranslatedSource
```

## Setup

In order to run the script the API details needs to be specified:
```python
# Replace these values with your actual firewall URL, username, and password
fw = {
   "firewallurl": "https://<fw-ip>:4444/webconsole/APIController",
    "username": "",
    "pwd": ""
}
```

On the firewall the API access needs to be enabled in *Backup and Firmware -> API configuration*:

For more information about setting up the API access, please refer to https://docs.sophos.com/nsg/sophos-firewall/18.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIUsingAPI/index.html