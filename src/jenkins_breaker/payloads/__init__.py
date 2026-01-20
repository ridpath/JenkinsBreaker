"""Payload generation modules for JenkinsBreaker."""

from jenkins_breaker.payloads.generator import (
    EncodingType,
    PayloadConfig,
    PayloadEncoder,
    PayloadGenerator,
    PayloadTemplate,
    PayloadType,
    create_generator,
)
from jenkins_breaker.payloads.jnlp_agent import (
    JNLPAgent,
    JNLPAgentConfig,
    JNLPConnectionResult,
    JNLPProtocolVersion,
    JNLPWebSocketAgent,
    create_jnlp_agent,
    establish_jnlp_c2,
)
from jenkins_breaker.payloads.meterpreter import (
    MeterpreterFormat,
    MeterpreterGenerator,
    MeterpreterPayloadType,
    MeterpreterPlatform,
    check_msfvenom_available,
    create_meterpreter_generator,
)
from jenkins_breaker.payloads.obfuscator import (
    GroovyObfuscator,
    ObfuscationResult,
    PayloadPolymorphism,
    generate_polymorphic_variants,
    obfuscate_payload,
)
from jenkins_breaker.payloads.powershell import PowerShellGenerator, generate_powershell_payload
from jenkins_breaker.payloads.reverse_shell import ReverseShellGenerator, generate_reverse_shell

__all__ = [
    "PayloadGenerator",
    "PayloadType",
    "EncodingType",
    "PayloadConfig",
    "PayloadEncoder",
    "PayloadTemplate",
    "create_generator",
    "ReverseShellGenerator",
    "generate_reverse_shell",
    "MeterpreterGenerator",
    "MeterpreterPayloadType",
    "MeterpreterPlatform",
    "MeterpreterFormat",
    "create_meterpreter_generator",
    "check_msfvenom_available",
    "PowerShellGenerator",
    "generate_powershell_payload",
    "GroovyObfuscator",
    "PayloadPolymorphism",
    "ObfuscationResult",
    "obfuscate_payload",
    "generate_polymorphic_variants",
    "JNLPProtocolVersion",
    "JNLPAgentConfig",
    "JNLPConnectionResult",
    "JNLPAgent",
    "JNLPWebSocketAgent",
    "create_jnlp_agent",
    "establish_jnlp_c2",
]
