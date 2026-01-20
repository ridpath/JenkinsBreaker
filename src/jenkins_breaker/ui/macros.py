"""
Macro recording and replay system for automation and reproducibility.
Allows operators to record complex attack sequences and replay them against multiple targets.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class MacroCommand:
    """Represents a single command in a macro."""

    command: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    result: Optional[str] = None
    success: bool = True


@dataclass
class Macro:
    """Represents a recorded macro session."""

    name: str
    description: str = ""
    commands: list[MacroCommand] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'description': self.description,
            'commands': [asdict(cmd) for cmd in self.commands],
            'created': self.created,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Macro':
        """Create from dictionary."""
        commands = [MacroCommand(**cmd) for cmd in data.get('commands', [])]
        return cls(
            name=data['name'],
            description=data.get('description', ''),
            commands=commands,
            created=data.get('created', datetime.now().isoformat()),
            metadata=data.get('metadata', {})
        )


class MacroRecorder:
    """
    Records console commands for later replay.

    Features:
    - Command recording with timestamps
    - Session state capture
    - Conditional execution
    - Variable substitution
    - Batch replay
    """

    def __init__(self, macros_dir: Optional[Path] = None):
        if macros_dir is None:
            macros_dir = Path.cwd() / 'macros'

        self.macros_dir = Path(macros_dir)
        self.macros_dir.mkdir(exist_ok=True)

        self.current_macro: Optional[Macro] = None
        self.recording = False

    def start_recording(self, name: str, description: str = "") -> bool:
        """
        Start recording a new macro.

        Args:
            name: Macro name
            description: Macro description

        Returns:
            True if recording started, False if already recording
        """
        if self.recording:
            return False

        self.current_macro = Macro(name=name, description=description)
        self.recording = True
        return True

    def stop_recording(self) -> Optional[Macro]:
        """
        Stop recording and return the macro.

        Returns:
            The recorded macro, or None if not recording
        """
        if not self.recording:
            return None

        self.recording = False
        macro = self.current_macro
        self.current_macro = None
        return macro

    def record_command(
        self,
        command: str,
        result: Optional[str] = None,
        success: bool = True
    ):
        """
        Record a command during active recording.

        Args:
            command: The command that was executed
            result: Result of the command
            success: Whether the command succeeded
        """
        if not self.recording or not self.current_macro:
            return

        macro_cmd = MacroCommand(
            command=command,
            result=result,
            success=success
        )

        self.current_macro.commands.append(macro_cmd)

    def save_macro(self, macro: Macro, filename: Optional[str] = None) -> Path:
        """
        Save a macro to disk.

        Args:
            macro: Macro to save
            filename: Optional filename (defaults to macro name)

        Returns:
            Path to saved file
        """
        if filename is None:
            safe_name = macro.name.replace(' ', '_').replace('/', '_')
            filename = f"{safe_name}.json"

        filepath = self.macros_dir / filename

        with open(filepath, 'w') as f:
            json.dump(macro.to_dict(), f, indent=2)

        return filepath

    def load_macro(self, filename: str) -> Optional[Macro]:
        """
        Load a macro from disk.

        Args:
            filename: Macro filename

        Returns:
            Loaded macro, or None if file doesn't exist
        """
        filepath = self.macros_dir / filename

        if not filepath.exists():
            return None

        try:
            with open(filepath) as f:
                data = json.load(f)

            return Macro.from_dict(data)
        except Exception:
            return None

    def list_macros(self) -> list[dict[str, str]]:
        """
        List all saved macros.

        Returns:
            List of macro metadata
        """
        macros = []

        for filepath in self.macros_dir.glob('*.json'):
            try:
                with open(filepath) as f:
                    data = json.load(f)

                macros.append({
                    'filename': filepath.name,
                    'name': data.get('name', filepath.stem),
                    'description': data.get('description', ''),
                    'commands': len(data.get('commands', [])),
                    'created': data.get('created', 'Unknown')
                })
            except Exception:
                continue

        return macros

    def delete_macro(self, filename: str) -> bool:
        """
        Delete a saved macro.

        Args:
            filename: Macro filename

        Returns:
            True if deleted, False if not found
        """
        filepath = self.macros_dir / filename

        if filepath.exists():
            filepath.unlink()
            return True

        return False


class MacroPlayer:
    """
    Replays recorded macros with variable substitution and error handling.
    """

    def __init__(self, console_executor):
        """
        Initialize macro player.

        Args:
            console_executor: Console instance that can execute commands
        """
        self.console = console_executor
        self.variables: dict[str, str] = {}

    def set_variable(self, name: str, value: str):
        """Set a variable for substitution."""
        self.variables[name] = value

    def substitute_variables(self, command: str) -> str:
        """
        Substitute variables in a command.

        Variables are in the format ${VAR_NAME}.

        Args:
            command: Command with variables

        Returns:
            Command with variables replaced
        """
        result = command
        for var_name, var_value in self.variables.items():
            result = result.replace(f"${{{var_name}}}", var_value)

        return result

    def play_macro(
        self,
        macro: Macro,
        stop_on_error: bool = False,
        dry_run: bool = False
    ) -> dict[str, Any]:
        """
        Play a macro.

        Args:
            macro: Macro to execute
            stop_on_error: Stop execution on first error
            dry_run: Show what would be executed without executing

        Returns:
            Execution report
        """
        report = {
            'macro': macro.name,
            'started': datetime.now().isoformat(),
            'commands_total': len(macro.commands),
            'commands_executed': 0,
            'commands_successful': 0,
            'commands_failed': 0,
            'errors': []
        }

        for idx, macro_cmd in enumerate(macro.commands, 1):
            command = self.substitute_variables(macro_cmd.command)

            if dry_run:
                print(f"[DRY RUN] Would execute: {command}")
                continue

            try:
                result = self.console.process_command(command)

                report['commands_executed'] += 1

                if result is False:
                    report['commands_failed'] += 1
                    if stop_on_error:
                        break
                else:
                    report['commands_successful'] += 1

            except Exception as e:
                report['commands_failed'] += 1
                report['errors'].append({
                    'command_index': idx,
                    'command': command,
                    'error': str(e)
                })

                if stop_on_error:
                    break

        report['completed'] = datetime.now().isoformat()
        return report

    def play_macro_batch(
        self,
        macro: Macro,
        target_list: list[dict[str, str]],
        stop_on_error: bool = False
    ) -> list[dict[str, Any]]:
        """
        Play a macro against multiple targets.

        Args:
            macro: Macro to execute
            target_list: List of target configurations with variables
            stop_on_error: Stop on first error

        Returns:
            List of execution reports for each target
        """
        reports = []

        for target in target_list:
            for var_name, var_value in target.items():
                self.set_variable(var_name, var_value)

            report = self.play_macro(macro, stop_on_error=stop_on_error)
            report['target'] = target
            reports.append(report)

            if stop_on_error and report['commands_failed'] > 0:
                break

        return reports


class MacroManager:
    """
    High-level interface for macro management.
    """

    def __init__(self, console_executor, macros_dir: Optional[Path] = None):
        self.recorder = MacroRecorder(macros_dir)
        self.player = MacroPlayer(console_executor)
        self.current_macro: Optional[Macro] = None

    def start_recording(self, name: str, description: str = "") -> bool:
        """Start recording a macro."""
        return self.recorder.start_recording(name, description)

    def stop_recording(self) -> bool:
        """Stop recording and save the macro."""
        macro = self.recorder.stop_recording()
        if macro:
            self.recorder.save_macro(macro)
            self.current_macro = macro
            return True
        return False

    def record_command(self, command: str, result: Optional[str] = None, success: bool = True):
        """Record a command if recording is active."""
        self.recorder.record_command(command, result, success)

    def play(
        self,
        macro_name: str,
        variables: Optional[dict[str, str]] = None,
        stop_on_error: bool = False
    ) -> Optional[dict[str, Any]]:
        """
        Play a macro by name.

        Args:
            macro_name: Name of the macro file
            variables: Variables to substitute
            stop_on_error: Stop on first error

        Returns:
            Execution report, or None if macro not found
        """
        macro = self.recorder.load_macro(macro_name)
        if not macro:
            return None

        if variables:
            for var_name, var_value in variables.items():
                self.player.set_variable(var_name, var_value)

        return self.player.play_macro(macro, stop_on_error=stop_on_error)

    def play_batch(
        self,
        macro_name: str,
        targets: list[dict[str, str]],
        stop_on_error: bool = False
    ) -> Optional[list[dict[str, Any]]]:
        """
        Play a macro against multiple targets.

        Args:
            macro_name: Name of the macro file
            targets: List of target variable sets
            stop_on_error: Stop on first error

        Returns:
            List of execution reports, or None if macro not found
        """
        macro = self.recorder.load_macro(macro_name)
        if not macro:
            return None

        return self.player.play_macro_batch(macro, targets, stop_on_error)

    def list(self) -> list[dict[str, str]]:
        """List all saved macros."""
        return self.recorder.list_macros()

    def delete(self, macro_name: str) -> bool:
        """Delete a macro."""
        return self.recorder.delete_macro(macro_name)

    def export_as_script(self, macro_name: str, output_file: Path) -> bool:
        """
        Export a macro as a shell script.

        Args:
            macro_name: Name of the macro
            output_file: Path to output script

        Returns:
            True if exported successfully
        """
        macro = self.recorder.load_macro(macro_name)
        if not macro:
            return False

        try:
            with open(output_file, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write(f"# Generated from macro: {macro.name}\n")
                f.write(f"# {macro.description}\n")
                f.write(f"# Created: {macro.created}\n\n")

                for cmd in macro.commands:
                    f.write(f"# {cmd.timestamp}\n")
                    f.write(f"jenkins-breaker-console -c '{cmd.command}'\n\n")

            output_file.chmod(0o755)
            return True

        except Exception:
            return False
