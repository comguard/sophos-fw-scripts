import requests
import xml.etree.ElementTree as ET
import pandas as pd

# Replace these values with your actual firewall URL, username, and password
fw = {
   "firewallurl": "https://<fw-ip>:4444/webconsole/APIController",
    "username": "",
    "pwd": ""
}

# Replace the placeholders in the XML payload with actual username and password
xml_payload_template = """<Request>
    <Login>
        <Username>{username}</Username>
        <Password>{password}</Password>
    </Login>
    <Get>
        <FirewallRule>
        </FirewallRule>
    </Get>
</Request>"""

def main():
    try:
        # Replace placeholders in the XML payload template with actual username and password
        xml_payload = xml_payload_template.format(username=fw["username"], password=fw["pwd"])

        # Make the HTTP POST request
        response = requests.post(fw["firewallurl"], data={"reqxml": xml_payload}, verify=False)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the XML response
            root = ET.fromstring(response.text)
            # print(response.text)

            # Extract NATRule elements from the XML response
            nat_rules = root.findall(".//FirewallRule")

            # Extract data from each NATRule element and store it in a list of dictionaries
            data_list = []
            for nat_rule in nat_rules:
                name = nat_rule.find("Name").text
                description = nat_rule.find("Description").text
                status = nat_rule.find("Status").text
                networkpolicy = nat_rule.find("NetworkPolicy")
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
