import platform
from azurenum.utils import const, output
from azurenum.utils.config import globalargs as globalargs
from azurenum.utils.config import globalconfig as globalconfig

### platform check
if platform.system() == 'Windows':
    IS_WINDOWS = True
else:
    IS_WINDOWS = False

### Printing Methods ###
def print_link(text):
    line = f"{const.CYAN}[+] {text}{const.NC}"
    print(line)
    if (globalargs and globalargs.output_text):
        globalconfig.log_content += line + "\n"

def print_simple(text):
    print(text)
    if (globalargs and globalargs.output_text):
        if IS_WINDOWS:
            globalconfig.log_content += text.replace("└──","+--").replace("├──","+--").replace("│", "|") + "\n"
        else:    
            globalconfig.log_content += text + "\n"

def print_header(text):
    print_simple("\n" + "#" * 49)
    print_simple(f"# {text}")
    print_simple("#" * 49 + "\n")

def print_info(text):
    line = f"{const.CYAN}[+]{const.NC} {text}"
    print(line)
    if (globalargs and globalargs.output_text):
        globalconfig.log_content += line + "\n"

def print_error(text):
    line = f"{const.RED}[-]{const.NC} {text}"
    print(line)
    if (globalargs and globalargs.output_text):
        globalconfig.log_content += line + "\n"

def print_warning(text):
    line = f"{const.ORANGE}[!]{const.NC} {text}"
    print(line)
    if (globalargs and globalargs.output_text):
        globalconfig.log_content += line + "\n"
    if (globalargs and globalargs.output_json):
        output.add_json_output(const.LEGACY_FINDINGS, {"description": text})




def print_banner():
    if globalargs.no_color:
        banner = '''
        AzurEnum
        Created by Enrique Hernández (SySS GmbH)
        '''
    else:
        banner = f'''

         ████████ ██████
       ██████████ ████████
     ████████████ ██████████
   ██████{const.RED}██████{const.NC}██ █████  █  █
  █████{const.RED}███{const.NC}███████ █ █ █ ██ ███   AzurEnum
 ██████{const.RED}███{const.NC}███████ ██ ███ ██ ███   Created by Enrique Hernández (SySS GmbH)
 ████████{const.RED}█████{const.NC}███ █ ███  █  ███
 ████████████{const.RED}███{const.NC}█
  ███████████{const.RED}███{const.NC}█
   █████{const.RED}███████{const.NC}██  {const.VERSION}
     ████████████
       ▄▄▄▄▄▄▄▄▄▄
         ████████

        '''

    print(banner)

