"""Post-exploitation modules for JenkinsBreaker."""

from jenkins_breaker.postex.auto_loot import JenkinsCredentialGrabber, auto_grab_jenkins_credentials
from jenkins_breaker.postex.credentials import Credential, CredentialExtractor, extract_credentials
from jenkins_breaker.postex.groovy_shell import GroovyCommand, GroovyShell, execute_groovy_command
from jenkins_breaker.postex.init_script import (
    InitScriptPersistence,
    InitScriptResult,
    PersistenceType,
    cleanup_init_scripts,
    install_boot_persistence,
)
from jenkins_breaker.postex.jenkins_decrypt import (
    DecryptedSecret,
    JenkinsDecryptor,
    decrypt_credentials_file,
    decrypt_jenkins_secret,
)
from jenkins_breaker.postex.lateral import (
    LateralMovementModule,
    LateralMovementResult,
    perform_lateral_movement,
)
from jenkins_breaker.postex.log_miner import (
    LogMiner,
    LogMiningResult,
    LogSecret,
    mine_all_logs,
    mine_job_logs,
)
from jenkins_breaker.postex.memory_hook import (
    MemoryHookResult,
    SecurityRealmHook,
    install_password_backdoor,
    install_token_backdoor,
    install_universal_backdoor,
)
from jenkins_breaker.postex.node_worm import (
    JenkinsNode,
    NodeExecutionResult,
    NodeStatus,
    NodeWorm,
    WormingResult,
    enumerate_jenkins_nodes,
    execute_on_all_nodes,
    worm_all_nodes,
)
from jenkins_breaker.postex.persistence import (
    PersistenceModule,
    PersistenceResult,
    install_persistence,
)
from jenkins_breaker.postex.reconnaissance import (
    NetworkInfo,
    ProcessInfo,
    ReconnaissanceModule,
    SystemInfo,
    perform_reconnaissance,
)
from jenkins_breaker.postex.ui_hijack import (
    UIHijacker,
    UIHijackResult,
    inject_credential_stealer,
    inject_login_keylogger,
    remove_all_injections,
)

__all__ = [
    "Credential",
    "CredentialExtractor",
    "extract_credentials",
    "SystemInfo",
    "NetworkInfo",
    "ProcessInfo",
    "ReconnaissanceModule",
    "perform_reconnaissance",
    "PersistenceResult",
    "PersistenceModule",
    "install_persistence",
    "LateralMovementResult",
    "LateralMovementModule",
    "perform_lateral_movement",
    "GroovyShell",
    "GroovyCommand",
    "execute_groovy_command",
    "MemoryHookResult",
    "SecurityRealmHook",
    "install_password_backdoor",
    "install_universal_backdoor",
    "install_token_backdoor",
    "UIHijackResult",
    "UIHijacker",
    "inject_login_keylogger",
    "inject_credential_stealer",
    "remove_all_injections",
    "LogSecret",
    "LogMiningResult",
    "LogMiner",
    "mine_job_logs",
    "mine_all_logs",
    "JenkinsNode",
    "NodeStatus",
    "NodeExecutionResult",
    "WormingResult",
    "NodeWorm",
    "enumerate_jenkins_nodes",
    "execute_on_all_nodes",
    "worm_all_nodes",
    "PersistenceType",
    "InitScriptResult",
    "InitScriptPersistence",
    "install_boot_persistence",
    "cleanup_init_scripts",
    "JenkinsDecryptor",
    "DecryptedSecret",
    "decrypt_jenkins_secret",
    "decrypt_credentials_file",
    "JenkinsCredentialGrabber",
    "auto_grab_jenkins_credentials",
]
