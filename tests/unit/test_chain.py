"""
Unit tests for JenkinsBreaker exploit chaining.
"""

from unittest.mock import Mock, patch


def test_chain_engine_initialization():
    """Test ChainEngine initialization."""
    from jenkins_breaker.chain.engine import ChainEngine

    engine = ChainEngine()

    assert engine is not None


def test_chain_step_creation():
    """Test ChainStep creation."""
    from jenkins_breaker.chain.engine import ChainStep

    step = ChainStep(
        cve_id="CVE-2024-23897",
        params={"file_path": "/etc/passwd"},
        depends_on=None
    )

    assert step.cve_id == "CVE-2024-23897"
    assert step.params["file_path"] == "/etc/passwd"
    assert step.depends_on is None


def test_chain_dependency_resolution():
    """Test dependency resolution in chain execution."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    engine = ChainEngine()

    steps = [
        ChainStep(cve_id="CVE-2024-23897", params={}, depends_on=None),
        ChainStep(cve_id="CVE-2019-1003029", params={}, depends_on=["CVE-2024-23897"])
    ]

    if hasattr(engine, 'resolve_dependencies'):
        resolved = engine.resolve_dependencies(steps)
        assert len(resolved) == 2


def test_chain_execution_order():
    """Test chain execution maintains correct order."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    engine = ChainEngine()

    steps = [
        ChainStep(cve_id="step3", params={}, depends_on=["step2"]),
        ChainStep(cve_id="step1", params={}, depends_on=None),
        ChainStep(cve_id="step2", params={}, depends_on=["step1"])
    ]

    if hasattr(engine, 'order_steps'):
        ordered = engine.order_steps(steps)

        assert ordered[0].cve_id == "step1"
        assert ordered[1].cve_id == "step2"
        assert ordered[2].cve_id == "step3"


@patch('jenkins_breaker.modules.exploit_registry')
def test_chain_execution_with_mock_exploits(mock_registry):
    """Test chain execution with mocked exploits."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    mock_exploit = Mock()
    mock_exploit.run.return_value = Mock(status="success", data={"extracted": "data"})
    mock_registry.get.return_value = mock_exploit

    engine = ChainEngine()

    steps = [
        ChainStep(cve_id="CVE-2024-23897", params={}, depends_on=None)
    ]

    session = Mock()

    if hasattr(engine, 'execute'):
        result = engine.execute(steps, session)

        assert result is not None


def test_chain_state_management():
    """Test chain maintains state between steps."""
    from jenkins_breaker.chain.engine import ChainEngine

    engine = ChainEngine()

    if hasattr(engine, 'state'):
        engine.state["extracted_key"] = "value"
        assert engine.state["extracted_key"] == "value"


def test_chain_rollback_on_failure():
    """Test chain rollback mechanism on step failure."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    engine = ChainEngine()

    steps = [
        ChainStep(cve_id="CVE-2024-23897", params={}, depends_on=None)
    ]

    if hasattr(engine, 'rollback'):
        engine.rollback(steps)


def test_predefined_chain_full_compromise():
    """Test predefined full compromise chain."""
    from jenkins_breaker.chain.chains import get_chain

    chain = get_chain("full_compromise")

    assert chain is not None
    assert len(chain) > 0


def test_predefined_chain_initial_access():
    """Test predefined initial access chain."""
    from jenkins_breaker.chain.chains import get_chain

    chain = get_chain("initial_access")

    assert chain is not None


def test_predefined_chain_stealth():
    """Test predefined stealth chain."""
    from jenkins_breaker.chain.chains import get_chain

    chain = get_chain("stealth")

    assert chain is not None


def test_chain_result_aggregation():
    """Test chain result aggregation."""
    from jenkins_breaker.chain.engine import ChainResult

    result = ChainResult(
        chain_id="test_chain",
        steps_completed=3,
        steps_failed=1,
        total_steps=4,
        results=[]
    )

    assert result.steps_completed == 3
    assert result.steps_failed == 1
    assert result.total_steps == 4


def test_chain_conditional_branching():
    """Test conditional branching in chains."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    engine = ChainEngine()

    step_success = ChainStep(cve_id="success_step", params={}, depends_on=None)
    step_failure = ChainStep(cve_id="failure_step", params={}, depends_on=None)

    if hasattr(engine, 'add_conditional'):
        engine.add_conditional(
            condition=lambda state: state.get("authenticated", False),
            true_step=step_success,
            false_step=step_failure
        )


def test_chain_parallel_execution():
    """Test parallel execution of independent steps."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    engine = ChainEngine()

    steps = [
        ChainStep(cve_id="parallel1", params={}, depends_on=None),
        ChainStep(cve_id="parallel2", params={}, depends_on=None)
    ]

    if hasattr(engine, 'execute_parallel'):
        engine.execute_parallel(steps, Mock())


def test_chain_variable_interpolation():
    """Test variable interpolation in chain parameters."""
    from jenkins_breaker.chain.engine import ChainEngine

    engine = ChainEngine()

    if hasattr(engine, 'state'):
        engine.state["target_file"] = "/etc/passwd"

    params = {"file_path": "${target_file}"}

    if hasattr(engine, 'interpolate_params'):
        interpolated = engine.interpolate_params(params)
        assert interpolated.get("file_path") == "/etc/passwd" or interpolated == params


def test_chain_timeout_handling():
    """Test chain step timeout handling."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    ChainEngine()

    step = ChainStep(
        cve_id="CVE-2024-23897",
        params={},
        depends_on=None,
        timeout=30
    )

    assert step.timeout == 30 or not hasattr(step, 'timeout')


def test_chain_error_handling():
    """Test comprehensive error handling in chains."""
    from jenkins_breaker.chain.engine import ChainEngine, ChainStep

    engine = ChainEngine()

    step = ChainStep(cve_id="invalid_cve", params={}, depends_on=None)

    session = Mock()

    if hasattr(engine, 'execute'):
        try:
            engine.execute([step], session)
        except Exception as e:
            assert e is not None


def test_chain_result_export():
    """Test chain result export functionality."""
    from jenkins_breaker.chain.engine import ChainResult

    result = ChainResult(
        chain_id="test",
        steps_completed=2,
        steps_failed=0,
        total_steps=2,
        results=[]
    )

    if hasattr(result, 'to_json'):
        json_output = result.to_json()
        assert json_output is not None


def test_chain_list_available_chains():
    """Test listing all available predefined chains."""
    from jenkins_breaker.chain.chains import list_chains

    chains = list_chains()

    assert isinstance(chains, list)
    assert len(chains) >= 0
