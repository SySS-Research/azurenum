from azurenum.utils import const, api, printer
from datetime import datetime, timedelta

# enumerate devices, types and compliancy
def enum_devices(devices, msGraphToken):
    printer.print_header("Devices")
    printer.print_link(f"Portal: {const.AZURE_PORTAL}/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices/menuId~/null")

    if devices == None:
        printer.print_error("Could not fetch devices")
        return
    
    printer.print_info(f"Number of devices: {len(devices)}")
    printer.print_info("Devices per Join-Type:")
    registeredDevices = [device for device in devices if device["trustType"] == "Workplace"]
    joinedDevices = [device for device in devices if device["trustType"] == "AzureAd"]
    hybridJoinedDevices = [device for device in devices if device["trustType"] == "ServerAd"]
    printer.print_info(f"- Registered: {len(registeredDevices)}")
    printer.print_info(f"- Joined: {len(joinedDevices)}")
    printer.print_info(f"- Hybrid-Joined: {len(hybridJoinedDevices)}")
    managedDevices = [device for device in devices if device["isManaged"] == True]
    managedPercent = "-"
    if len(devices) != 0:
        managedPercent = round(len(managedDevices) / len(devices) * 100, 2)
    printer.print_info(f"Managed devices: {len(managedDevices)}/{len(devices)} ({managedPercent} %)")
    compliantDevices = [device for device in devices if device["isCompliant"] == True]
    nonCompliantDevices = [device for device in devices if device["isCompliant"] == False]
    deviceNumWithComplianceData = len(compliantDevices) + len(nonCompliantDevices)
    compliantPercent = "-"
    if deviceNumWithComplianceData != 0:
        compliantPercent = round(len(compliantDevices) / deviceNumWithComplianceData * 100, 2)
    printer.print_info(f"Compliant devices: {len(compliantDevices)}/{deviceNumWithComplianceData} ({compliantPercent} %)")
    
    current_datetime = datetime.now()
    # Calculate 6 months ago from the current date
    six_months_ago = current_datetime - timedelta(days=6*30)  # Approximate 30 days in a month
    formatted_datetime = six_months_ago.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    staleDevices = api.get_msgraph_value("/devices", {
        "$top": "999",
        "$filter": f"approximateLastSignInDateTime le {formatted_datetime}"
    }, msGraphToken)
    staleProcent = "-"
    if len(devices) != 0:
        staleProcent = round(len(staleDevices or [])/len(devices) * 100, 2)
    printer.print_info(f"Stale Devices: {len(staleDevices)}/{len(devices)} ({staleProcent} %) -- last activity older than 6 months")

