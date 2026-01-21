from azurenum.utils import const, printer

# show named locations - maybe show more details in the future?
def enum_named_locations(namedLocations):
    printer.print_header("Named Locations")
    printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_ConditionalAccess/NamedLocationsBlade")
    
    if namedLocations == None:
        printer.print_error("Could not fetch named locations")
        return
    
    if len(namedLocations) == 0:
        printer.print_info("No named locations")
        return
    printer.print_info(f"{len(namedLocations)} Named locations found")
    for location in namedLocations:
        displayName = location["displayName"]
        locationType = location["@odata.type"]
        if locationType == "#microsoft.graph.ipNamedLocation":
            ranges = ' '.join([ipRange["cidrAddress"] for ipRange in location["ipRanges"]])
            isTrusted = "Trusted" if location["isTrusted"] else "Not trusted"
            printer.print_info(f"- {const.GREEN}[IP - {isTrusted}] {displayName}{const.NC} {ranges}")
        elif locationType == "#microsoft.graph.countryNamedLocation":
            countries = ' '.join(location["countriesAndRegions"])
            printer.print_info(f"- {const.GREEN}[COUNTRY] {displayName}{const.NC} {countries}")
        else:
            printer.print_info(f"- {const.GREEN}[Unknown Location type: {locationType}] {displayName}{const.NC}")
