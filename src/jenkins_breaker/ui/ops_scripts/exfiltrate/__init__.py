"""Exfiltrate operator scripts."""

from .memory_dump import MemoryDump
from .token_stealer import TokenStealer
from .certificate_harvest import CertificateHarvest
from .shadow_extract import ShadowExtract
from .full_cred_dump import FullCredDump
from .browser_history import BrowserHistory
from .clipboard_monitor import ClipboardMonitor
from .keylogger import Keylogger
from .screenshot_capture import ScreenshotCapture
from .webcam_capture import WebcamCapture
from .audio_recording import AudioRecording
from .file_search import FileSearch
from .database_dump import DatabaseDump
from .source_code_exfil import SourceCodeExfil
from .email_archive import EmailArchive
from .chat_history import ChatHistory
from .s3_bucket_enum import S3BucketEnum
from .gcp_storage import GCPStorage
from .azure_blob import AzureBlob
from .secrets_manager_dump import SecretsManagerDump

__all__ = ['MemoryDump', 'TokenStealer', 'CertificateHarvest', 'ShadowExtract', 'FullCredDump', 'BrowserHistory', 'ClipboardMonitor', 'Keylogger', 'ScreenshotCapture', 'WebcamCapture', 'AudioRecording', 'FileSearch', 'DatabaseDump', 'SourceCodeExfil', 'EmailArchive', 'ChatHistory', 'S3BucketEnum', 'GCPStorage', 'AzureBlob', 'SecretsManagerDump']
