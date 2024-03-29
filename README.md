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

## Requisites

- python3
- `msal` python library
- A valid Azure credential set

Not a requisite, but running AzurEnum on Linux is recommended.

The amount of output of the tool will depend on the privileges of your Azure user and the configuration of the target tenant. Although AzurEnum can run as any user, you will get the most out of it when running with global reader privileges or greater reader access.

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

# Run with ROPC authentication (username & password)
python3 azurenum.py -u myuser@mytenant.com -p mypassword -t xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Read colored txt output (in linux)
less -r out.txt
```

## Future work

- JSON output was included as an experimental feature to include machine readable output of findings with an assigned severity. This is however not the main goal of AzurEnum and thus is not mantained as much as the text output. This feature will either get removed or improved later on.
- Add arguments to set FOCI client to authenticate to and access or refresh token to run with.
- Enumerate interesting owner relationships
- Unfold group members in administrative roles and PIM assignments
- Explicitly mark modifiable groups that have Entra ID roles or PIM assignments

## Credits

Enrique Hernández, SySS GmbH

## License

MIT License