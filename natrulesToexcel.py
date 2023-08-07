import requests
import xml.etree.ElementTree as ET
import pandas as pd

# Replace these values with your actual firewall URL, username, and password
fw = {
   "firewallurl": "",
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
        <NATRule>
        </NATRule>
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

            # Extract NATRule elements from the XML response
            nat_rules = root.findall(".//NATRule")

            # Extract data from each NATRule element and store it in a list of dictionaries
            data_list = []
            for nat_rule in nat_rules:
                name = nat_rule.find("Name").text
                description = nat_rule.find("Description").text
                ip_family = nat_rule.find("IPFamily").text
                status = nat_rule.find("Status").text
                position = nat_rule.find("Position").text
                linked_firewall_rule = nat_rule.find("LinkedFirewallrule").text
                translated_destination = nat_rule.find("TranslatedDestination").text
                translated_service = nat_rule.find("TranslatedService").text
                outbound_interfaces = [interface.text for interface in nat_rule.findall("OutboundInterfaces/Interface")]
                override_interface_nat_policy = nat_rule.find("OverrideInterfaceNATPolicy").text
                translated_source = nat_rule.find("TranslatedSource").text

                data_list.append({
                    "Name": name,
                    "Description": description,
                    "IPFamily": ip_family,
                    "Status": status,
                    "Position": position,
                    "LinkedFirewallrule": linked_firewall_rule,
                    "TranslatedDestination": translated_destination,
                    "TranslatedService": translated_service,
                    "OutboundInterfaces": ",".join(outbound_interfaces),
                    "OverrideInterfaceNATPolicy": override_interface_nat_policy,
                    "TranslatedSource": translated_source
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
