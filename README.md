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

## Requisites

- python3
- `msal` python library
- A valid Azure credential set

Not a requisite, but running AzurEnum on Linux is recommended.

## Installation

In case `msal` is not installed already

```sh
pip3 install msal
```

## Usage

```sh
# Get help
python3 azurenum.py -h

# Run with output logging (text & json)
python3 azurenum.py -o out.txt -j out.json

# Run with no colors
python3 azurenum.py -nc

# Run with custom User-Agent
python3 azurenum.py -ua "My-UA"

# Read colored txt output (in linux)
less -r out.txt
```

# Known issues

- "Users with no MFA methods" sometimes gets to 100 % (erroneously)
- "No MFA Methods" checks for administrative users always return no MFA when running as a low privilige user
- Unfold group members in administrative roles and PIM assignments
- Explicitly mark modifiable groups that have Entra ID roles or PIM assignments

## Future work

- JSON output was included as an experimental feature to include machine readable output of findings with an assigned severity. This is however not the main goal of AzurEnum and thus is not mantained as much as the text output. This feature will either get removed or improved later on.
- Add arguments to set FOCI client to authenticate to and access or refresh token to run with.
- Enumerate interesting owner relationships