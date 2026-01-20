"""Exploit chaining engine for orchestrating multi-stage attacks.

Provides dependency resolution, state management, and rollback capabilities
for executing complex attack chains.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class ChainStepStatus(Enum):
    """Status of a chain step."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class ChainStep:
    """Represents a single step in an exploit chain."""
    id: str
    name: str
    exploit_id: Optional[str] = None
    function: Optional[Callable] = None
    depends_on: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    required_state: dict[str, Any] = field(default_factory=dict)
    provides_state: list[str] = field(default_factory=list)
    rollback_function: Optional[Callable] = None
    on_failure: str = "stop"
    timeout: int = 300

    status: ChainStepStatus = ChainStepStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None


@dataclass
class ChainResult:
    """Result of executing an exploit chain."""
    success: bool
    steps_executed: int
    steps_failed: int
    steps_skipped: int
    total_time: float
    state: dict[str, Any]
    step_results: list[dict[str, Any]]
    errors: list[str] = field(default_factory=list)


class ChainEngine:
    """Engine for executing exploit chains with dependency management."""

    def __init__(self, session: Any):
        """Initialize chain engine.

        Args:
            session: Authenticated Jenkins session
        """
        self.session = session
        self.state: dict[str, Any] = {}
        self.executed_steps: list[ChainStep] = []

    def _resolve_dependencies(self, steps: list[ChainStep]) -> list[ChainStep]:
        """Resolve step dependencies and order steps.

        Args:
            steps: List of ChainStep objects

        Returns:
            Ordered list of steps based on dependencies
        """
        resolved = []
        remaining = steps.copy()

        while remaining:
            made_progress = False

            for step in remaining[:]:
                dependencies_met = all(
                    any(s.id == dep_id and s.status == ChainStepStatus.SUCCESS
                        for s in resolved)
                    for dep_id in step.depends_on
                ) if step.depends_on else True

                if dependencies_met:
                    resolved.append(step)
                    remaining.remove(step)
                    made_progress = True

            if not made_progress and remaining:
                raise ValueError(
                    f"Circular dependency detected or missing dependencies for steps: "
                    f"{[s.id for s in remaining]}"
                )

        return resolved

    def _check_required_state(self, step: ChainStep) -> bool:
        """Check if required state is available.

        Args:
            step: ChainStep to check

        Returns:
            True if all required state is available
        """
        for key, value in step.required_state.items():
            if key not in self.state:
                return False
            if value is not None and self.state[key] != value:
                return False
        return True

    def _execute_step(self, step: ChainStep) -> bool:
        """Execute a single chain step.

        Args:
            step: ChainStep to execute

        Returns:
            True if successful, False otherwise
        """
        step.status = ChainStepStatus.RUNNING
        step.start_time = time.time()

        try:
            if not self._check_required_state(step):
                step.status = ChainStepStatus.SKIPPED
                step.error = "Required state not available"
                return False

            if step.function:
                params = {**step.params, "session": self.session, "state": self.state}
                step.result = step.function(**params)
            elif step.exploit_id:
                from jenkins_breaker.modules import exploit_registry
                exploit = exploit_registry.get_exploit(step.exploit_id)
                if exploit:
                    step.result = exploit.run(self.session, **step.params)
                else:
                    raise ValueError(f"Exploit {step.exploit_id} not found")
            else:
                raise ValueError("Step must have either function or exploit_id")

            for state_key in step.provides_state:
                if hasattr(step.result, state_key):
                    self.state[state_key] = getattr(step.result, state_key)
                elif isinstance(step.result, dict) and state_key in step.result:
                    self.state[state_key] = step.result[state_key]

            step.status = ChainStepStatus.SUCCESS
            step.end_time = time.time()
            return True

        except Exception as e:
            step.status = ChainStepStatus.FAILED
            step.error = str(e)
            step.end_time = time.time()
            return False

    def _rollback_step(self, step: ChainStep) -> None:
        """Rollback a chain step.

        Args:
            step: ChainStep to rollback
        """
        if step.rollback_function:
            try:
                step.rollback_function(session=self.session, state=self.state)
                step.status = ChainStepStatus.ROLLED_BACK
            except Exception:
                pass

    def _rollback_chain(self, executed_steps: list[ChainStep]) -> None:
        """Rollback all executed steps in reverse order.

        Args:
            executed_steps: List of executed steps to rollback
        """
        for step in reversed(executed_steps):
            if step.status == ChainStepStatus.SUCCESS:
                self._rollback_step(step)

    def execute(self, steps: list[ChainStep], rollback_on_failure: bool = False) -> ChainResult:
        """Execute exploit chain.

        Args:
            steps: List of ChainStep objects to execute
            rollback_on_failure: Whether to rollback on failure

        Returns:
            ChainResult with execution details
        """
        start_time = time.time()
        ordered_steps = self._resolve_dependencies(steps)

        executed_count = 0
        failed_count = 0
        skipped_count = 0
        errors = []

        for step in ordered_steps:
            success = self._execute_step(step)
            self.executed_steps.append(step)

            if success:
                executed_count += 1
            elif step.status == ChainStepStatus.FAILED:
                failed_count += 1
                errors.append(f"{step.name}: {step.error}")

                if step.on_failure == "stop":
                    if rollback_on_failure:
                        self._rollback_chain(self.executed_steps)
                    break
            elif step.status == ChainStepStatus.SKIPPED:
                skipped_count += 1

        end_time = time.time()

        step_results = []
        for step in self.executed_steps:
            step_results.append({
                "id": step.id,
                "name": step.name,
                "status": step.status.value,
                "result": step.result,
                "error": step.error,
                "duration": (step.end_time - step.start_time) if step.end_time and step.start_time else None
            })

        return ChainResult(
            success=(failed_count == 0),
            steps_executed=executed_count,
            steps_failed=failed_count,
            steps_skipped=skipped_count,
            total_time=end_time - start_time,
            state=self.state,
            step_results=step_results,
            errors=errors
        )

    def execute_with_branching(
        self,
        steps: list[ChainStep],
        success_branch: Optional[list[ChainStep]] = None,
        failure_branch: Optional[list[ChainStep]] = None
    ) -> ChainResult:
        """Execute chain with conditional branching.

        Args:
            steps: Main chain steps
            success_branch: Steps to execute if main chain succeeds
            failure_branch: Steps to execute if main chain fails

        Returns:
            ChainResult with execution details
        """
        result = self.execute(steps)

        if result.success and success_branch:
            success_result = self.execute(success_branch)
            result.steps_executed += success_result.steps_executed
            result.step_results.extend(success_result.step_results)
        elif not result.success and failure_branch:
            failure_result = self.execute(failure_branch)
            result.steps_executed += failure_result.steps_executed
            result.step_results.extend(failure_result.step_results)

        return result


def create_step(
    step_id: str,
    name: str,
    exploit_id: Optional[str] = None,
    function: Optional[Callable] = None,
    depends_on: Optional[list[str]] = None,
    params: Optional[dict[str, Any]] = None,
    required_state: Optional[dict[str, Any]] = None,
    provides_state: Optional[list[str]] = None,
    rollback_function: Optional[Callable] = None,
    on_failure: str = "stop"
) -> ChainStep:
    """Factory function to create a ChainStep.

    Args:
        step_id: Unique step identifier
        name: Human-readable step name
        exploit_id: Optional CVE ID for exploit module
        function: Optional function to execute
        depends_on: List of step IDs this step depends on
        params: Parameters to pass to exploit/function
        required_state: Required state keys and values
        provides_state: State keys this step provides
        rollback_function: Optional function for rollback
        on_failure: Behavior on failure ("stop", "continue")

    Returns:
        ChainStep instance
    """
    return ChainStep(
        id=step_id,
        name=name,
        exploit_id=exploit_id,
        function=function,
        depends_on=depends_on or [],
        params=params or {},
        required_state=required_state or {},
        provides_state=provides_state or [],
        rollback_function=rollback_function,
        on_failure=on_failure
    )


def execute_chain(session: Any, steps: list[ChainStep], rollback_on_failure: bool = False) -> ChainResult:
    """Factory function to execute a chain.

    Args:
        session: Authenticated Jenkins session
        steps: List of chain steps
        rollback_on_failure: Whether to rollback on failure

    Returns:
        ChainResult
    """
    engine = ChainEngine(session)
    return engine.execute(steps, rollback_on_failure)
