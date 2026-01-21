import copy
from azurenum.utils import printer
from azurenum.utils.config import globalargs as globalargs
from azurenum.utils.config import globalconfig as globalconfig
# helper method for raw json output
def add_json_raw_output(key, json):
    globalconfig.json_content
    rawKey = f"raw-{key}"
    if globalargs.output_json:
        exists = False
        for obj in globalconfig.json_content:
            if obj == rawKey:
                exists = True
        if exists:
            printer.print_error("Key already exists in global json_content!")
        else:
            globalconfig.json_content[rawKey] = json



def add_json_output(key, jsonObj):
    globalconfig.json_content
    aeKey = f"ae-{key}" # use prefix to mark output as 'azurenum generated'
    copiedJson = copy.deepcopy(jsonObj)
    if globalargs.output_json:
        exists = False
        for obj in globalconfig.json_content:
            if obj == aeKey:
                exists = True
                globalconfig.json_content[aeKey].append(copiedJson)
                break
        if exists == False:
            globalconfig.json_content[aeKey] = []
            globalconfig.json_content[aeKey].append(copiedJson)
