"""Persistence operator scripts."""

from .backdoor_user import BackdoorUser
from .cron_backdoor import CronBackdoor
from .ssh_key_inject import SSHKeyInject
from .systemd_service import SystemdService
from .ld_preload_rootkit import LDPreloadRootkit
from .pam_backdoor import PAMBackdoor
from .bashrc_injection import BashrcInjection
from .startup_scripts import StartupScripts
from .registry_run_keys import RegistryRunKeys
from .wmi_subscription import WMISubscription
from .scheduled_task_persist import ScheduledTaskPersist
from .golden_ticket import GoldenTicket
from .silver_ticket import SilverTicket
from .skeleton_key import SkeletonKey
from .jenkins_pipeline_backdoor import JenkinsPipelineBackdoor
from .git_hook_backdoor import GitHookBackdoor
from .docker_container_persist import DockerContainerPersist
from .k8s_admission_webhook import K8sAdmissionWebhook
from .lambda_backdoor import LambdaBackdoor
from .cloud_function_persist import CloudFunctionPersist

__all__ = [
    'BackdoorUser',
    'CronBackdoor',
    'SSHKeyInject',
    'SystemdService',
    'LDPreloadRootkit',
    'PAMBackdoor',
    'BashrcInjection',
    'StartupScripts',
    'RegistryRunKeys',
    'WMISubscription',
    'ScheduledTaskPersist',
    'GoldenTicket',
    'SilverTicket',
    'SkeletonKey',
    'JenkinsPipelineBackdoor',
    'GitHookBackdoor',
    'DockerContainerPersist',
    'K8sAdmissionWebhook',
    'LambdaBackdoor',
    'CloudFunctionPersist',
]
