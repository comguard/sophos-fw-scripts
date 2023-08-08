import requests
import xml.etree.ElementTree as ET
import pandas as pd

# Replace these values with your actual firewall URL, username, and password
fw = {
   "firewallurl": "https://<fw-ip>:4444/webconsole/APIController",
    "username": "",
    "pwd": ""
}

# Creates two XLM payload templates for FirewallRules and FirewallRuleGroups
xml_payload_template_fwrules = """<Request>
    <Login>
        <Username>{username}</Username>
        <Password>{password}</Password>
    </Login>
    <Get>
        <FirewallRule>
        </FirewallRule>
    </Get>
</Request>"""

xml_payload_template_fwrulegroups = """<Request>
    <Login>
        <Username>{username}</Username>
        <Password>{password}</Password>
    </Login>
    <Get>
        <FirewallRuleGroup>
        </FirewallRuleGroup>
    </Get>
</Request>"""

def main():
    try:
        # Construct payload for fetching groups of firewall rules
        xml_payload_fwrulegroups = xml_payload_template_fwrulegroups.format(username=fw["username"], password=fw["pwd"])
        
        # Make the HTTP POST request and save the response for later usage
        response_groups = requests.post(fw["firewallurl"], data={"reqxml": xml_payload_fwrulegroups}, verify=False)
        
        # After processing fw_groups includes all rule groups with security policies 
        fw_groups = ""
        if response_groups.status_code == 200:
            fw_groups_root = ET.fromstring(response_groups.text)
            fw_groups = fw_groups_root.findall(".//FirewallRuleGroup")
        else:
            print(f"Failed to get the response. Status code: {response.status_code}")

        # Construct payload for fetching firewall rules
        xml_payload_fwrules = xml_payload_template_fwrules.format(username=fw["username"], password=fw["pwd"])

        # Make the HTTP POST request
        response = requests.post(fw["firewallurl"], data={"reqxml": xml_payload_fwrules}, verify=False)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the XML response
            root = ET.fromstring(response.text)
            # print(response.text)

            # Extract FirewallRule elements from the XML response
            fw_rules = root.findall(".//FirewallRule")

            # Extract data from each FirewallRule element and store it in a list of dictionaries
            data_list = []
            for fw_rule in fw_rules:
                name = fw_rule.find("Name").text

                # Loop through firewall groups, and find the correct one
                group = ""
                for fw_group in fw_groups:
                    for policy in fw_group.find("SecurityPolicyList").findall("SecurityPolicy"):
                        if policy.text == name:
                            group = fw_group.find("Name").text

                description = fw_rule.find("Description").text
                status = fw_rule.find("Status").text
                networkpolicy = fw_rule.find("NetworkPolicy")
                action = logtraffic = sourcezones = sourcenetworks = ""
                destinationzones = destinationnetworks = services = ""
                webfilter = applicationcontrol = ""
                # scanvirus = zerodayprotection = intrusionprevention = ""
                if not (networkpolicy is None):
                    if not (networkpolicy.find("Action") is None):
                        action = networkpolicy.find("Action").text
                    if not (networkpolicy.find("LogTraffic") is None):
                        logtraffic = networkpolicy.find("LogTraffic").text
                    if not (networkpolicy.find("SourceZones") is None):
                        zones = networkpolicy.find("SourceZones").findall("Zone")
                        first = True
                        for zone in zones:
                            if not first:
                                sourcezones += ", "
                            sourcezones += zone.text
                            first = False
                    else:
                        sourcezones = "ANY"
                    if not (networkpolicy.find("SourceNetworks") is None):
                        networks = networkpolicy.find("SourceNetworks").findall("Network")
                        first = True
                        for network in networks:
                            if not first:
                                sourcenetworks += ", "
                            sourcenetworks += network.text
                            first = False
                    else:
                        sourcenetworks = "ANY"
                    if not (networkpolicy.find("DestinationZones") is None):
                        zones = networkpolicy.find("DestinationZones").findall("Zone")
                        first = True
                        for zone in zones:
                            if not first:
                                destinationzones += ", "
                            destinationzones += zone.text
                            first = False
                    else:
                        destinationzones = "ANY"
                    if not (networkpolicy.find("DestinationNetworks") is None):
                        networks = networkpolicy.find("DestinationNetworks").findall("Network")
                        first = True
                        for network in networks:
                            if not first:
                                destinationnetworks += ", "
                            destinationnetworks += network.text
                            first = False
                    else:
                        destinationnetworks = "ANY"
                    if not (networkpolicy.find("Services") is None):
                        serviceslist = networkpolicy.find("Services").findall("Service")
                        first = True
                        for service in serviceslist:
                            if not first:
                                services += ", "
                            services += service.text
                            first = False
                    else:
                        services = "ANY"
                    if not (networkpolicy.find("WebFilter") is None):
                        webfilter = networkpolicy.find("WebFilter").text
                    if not (networkpolicy.find("ApplicationControl") is None):
                        applicationcontrol = networkpolicy.find("ApplicationControl").text

                data_list.append({
                    "Group": group,
                    "Name": name,
                    "Description": description,
                    "Status": status,
                    "Action": action,
                    "LogTraffic": logtraffic,
                    "SourceZones": sourcezones,
                    "SourceNetworks": sourcenetworks,
                    "DestinationZones": destinationzones,
                    "DestinationNetworks": destinationnetworks,
                    "Services": services,
                    "WebFilter": webfilter,
                    "ApplicationControl": applicationcontrol,
                })

            # Convert the list of dictionaries to a DataFrame
            df = pd.DataFrame(data_list)

            # Convert DataFrame to Excel
            excel_file_name = "firewall_rules.xlsx"
            df.to_excel(excel_file_name, index=False)

            print(f"Excel file '{excel_file_name}' created successfully.")

        else:
            print(f"Failed to get the response. Status code: {response.status_code}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
