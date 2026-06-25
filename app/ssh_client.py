import paramiko
import socket
import time
import re


class SSHClientWrapper:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        self.shell = None

    def connect(self, timeout=10):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException:
            self._connect_keyboard_interactive(timeout)
        except (paramiko.SSHException, socket.timeout):
            raise
        # open an interactive shell to better handle devices that change prompts
        # request an interactive shell
        self.shell = self.client.invoke_shell()
        time.sleep(0.5)
        # clear initial banner
        self._drain()
        # try to disable paging on Huawei VRP so 'display' outputs are not paged
        try:
            # 'screen-length 0 temporary' is commonly supported on VRP
            self.shell.send(b'screen-length 0 temporary\n')
            time.sleep(0.2)
            self._drain()
        except Exception:
            pass

    def _connect_keyboard_interactive(self, timeout=10):
        if self.client:
            self.client.close()

        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        transport.auth_timeout = timeout
        transport.start_client(timeout=timeout)

        def handler(title, instructions, prompts):
            return [self.password for _prompt, _echo in prompts]

        transport.auth_interactive(self.username, handler)
        if not transport.is_authenticated():
            transport.close()
            raise paramiko.AuthenticationException("keyboard-interactive authentication failed")

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client._transport = transport

    def _drain(self):
        out = ''
        if self.shell is None:
            return out
        while self.shell.recv_ready():
            out += self.shell.recv(65536).decode(errors='ignore')
            time.sleep(0.05)
        return out

    def run(self, command, timeout=3):
        """Run a command via shell and return full output as text."""
        if self.shell is None:
            raise RuntimeError('Not connected')
        # send command
        # send the command and read output. handle --More-- by sending space
        self.shell.send((command + '\n').encode('utf-8'))
        end_time = time.time() + timeout
        output = ''
        while time.time() < end_time:
            while self.shell.recv_ready():
                data = self.shell.recv(65536).decode(errors='ignore')
                output += data
            # if device sent a pager prompt, advance it
            if '--More--' in output or '\x1b[0K--More--' in output:
                try:
                    self.shell.send(b' ')
                except Exception:
                    pass
                end_time = time.time() + timeout
            # Huawei VRP prompts can be <VRP>, [~VRP], [*VRP], or classic #.
            if re.search(r'(<[^>]+>|\[[^\]]+\]|#)\s*$', output.strip()):
                break
            time.sleep(0.1)

        # clean output from ANSI escape sequences and control chars
        cleaned = self._clean_output(output)
        # remove leading echoed command if present
        cleaned = self._strip_echoed_command(cleaned, command)
        return cleaned

    def _clean_output(self, text: str) -> str:
        # remove common ANSI escape sequences
        ansi_re = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        no_ansi = ansi_re.sub('', text)
        # remove other control characters except newline and tab
        no_ctrl = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', no_ansi)
        # normalize CRLF
        no_ctrl = no_ctrl.replace('\r\n', '\n').replace('\r', '\n')
        return no_ctrl

    def _strip_echoed_command(self, text: str, command: str) -> str:
        # if the command appears near the start (echoed), remove that line
        lines = text.splitlines()
        # find first occurrence of command in lines
        cmd = command.strip()
        for i, ln in enumerate(lines[:6]):
            if cmd in ln:
                # remove that line
                del lines[i]
                break
        return '\n'.join(lines)

    def close(self):
        try:
            if self.shell:
                self.shell.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
