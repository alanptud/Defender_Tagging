# Defender_Tagging
 Tag devices in Defender for Endpoint based on User attribute

Line 2 - specify the tenant ID

Line 3 & 4 - create variabled in an automation account in Azure to store the Client ID and Client secret and call them from these lines

The Application in Azure should have the appropriate permissions on the Graph API  to get the device information, user information and set the tagging on the device

Line 137 - specify the name of the device group that contains all intuned devices that you wish to target with the script

