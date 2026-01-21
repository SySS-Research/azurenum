# AzurEnum

## What is this?

Enumerate some Entra ID (formerly Azure AD) stuff fast, including:

- General information such as number of users, groups, apps, Entra ID license, tenant ID ...
- General security settings such as group creation, consent policy, guest access ...
- Administrative Entra ID roles
- PIM assignments
- Sync status of administrative users
- MFA status of administrative users
- Administrative units
- Dynamic groups
- Named locations
- Conditional access policies
- Credentials in object attributes

You can find a quite detailed blog post about the tool here [https://blog.syss.com/posts/introducing-azurenum/](https://blog.syss.com/posts/introducing-azurenum/).

An update on the changes of the new version (v1.1.5) can be found here [https://blog.syss.com/posts/azurenum-development/](https://blog.syss.com/posts/azurenum-update/).

## Prerequisites

- python3
- pipx
- A valid Azure credential set

Not a requisite, but running AzurEnum on Linux is recommended.

The amount of output of the tool will depend on the privileges of your Azure user and the configuration of the target tenant. Although AzurEnum can run as any user, you will get the most out of it when running with global reader privileges or greater reader access.


## Installation

It's recommended to install AzurEnum with pipx:

```sh
git clone https://github.com/SySS-Research/azurenum.git
cd azurenum
pipx install .

# OR
pipx install git+https://github.com/SySS-Research/azurenum.git
```

## Usage

```sh
# Get help
azurenum -h

# Recommended Usage
azurenum -u myuser@mytenant.com -p -rd 3 -o out.log -j out.json

# Run with output logging (text & json)
azurenum -o out.txt -j out.json

# Run with no colors
azurenum -nc

# Run with custom User-Agent
azurenum -ua "My-UA"

# Run with ROPC authentication (username & password)
azurenum -u myuser@mytenant.com -p mypassword -t xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Enumerate additional policies and IDP (only needs to be specified if NOT using NAA/interactive login (which is default))
azurenum -pol -idp

# Automate interactive login and query everything
azurenum -u myuser@mytenant.com -p mypassword 

# Read colored txt output (in linux)
less -r out.txt
```

## Credits

Enrique Hernández, SySS GmbH  
Domenik Jockers, SySS GmbH

## License

MIT License
