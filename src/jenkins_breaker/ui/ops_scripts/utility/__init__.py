"""Utility operator scripts."""

from .tty_stabilize import TTYStabilize
from .clear_tracks import ClearTracks
from .upload_script import UploadScript
from .port_forward import PortForward
from .socks_proxy import SOCKSProxy
from .chisel_tunnel import ChiselTunnel
from .ssh_tunnel import SSHTunnel
from .reverse_ssh import ReverseSSH
from .file_transfer import FileTransfer
from .packet_capture import PacketCapture
from .traffic_intercept import TrafficIntercept
from .process_injection import ProcessInjection
from .persistence_menu import PersistenceMenu
from .cleanup_tool import CleanupTool
from .anti_forensics import AntiForensics
from .log_tamper import LogTamper
from .timestamp_manip import TimestampManip
from .evidence_plant import EvidencePlant
from .report_generator import ReportGenerator
from .screenshot_loop import ScreenshotLoop

__all__ = ['TTYStabilize', 'ClearTracks', 'UploadScript', 'PortForward', 'SOCKSProxy', 'ChiselTunnel', 'SSHTunnel', 'ReverseSSH', 'FileTransfer', 'PacketCapture', 'TrafficIntercept', 'ProcessInjection', 'PersistenceMenu', 'CleanupTool', 'AntiForensics', 'LogTamper', 'TimestampManip', 'EvidencePlant', 'ReportGenerator', 'ScreenshotLoop']
