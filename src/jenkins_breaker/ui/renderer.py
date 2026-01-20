"""
Dynamic form renderer for auto-generating UI from exploit metadata.
Automatically creates forms and parameter inputs based on exploit module definitions.
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from jenkins_breaker.modules.base import ExploitMetadata, exploit_registry


class FieldType(Enum):
    """Form field types."""

    TEXT = "text"
    PASSWORD = "password"
    NUMBER = "number"
    BOOLEAN = "boolean"
    SELECT = "select"
    TEXTAREA = "textarea"
    FILE = "file"
    URL = "url"
    EMAIL = "email"
    MULTISELECT = "multiselect"


@dataclass
class ValidationRule:
    """Field validation rule."""

    type: str
    value: Any
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "value": self.value,
            "message": self.message
        }


@dataclass
class FieldOption:
    """Option for select/multiselect fields."""

    label: str
    value: Any
    disabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "label": self.label,
            "value": self.value,
            "disabled": self.disabled
        }


@dataclass
class FormField:
    """Represents a form input field."""

    name: str
    label: str
    field_type: FieldType
    required: bool = False
    default_value: Any = None
    placeholder: str = ""
    help_text: str = ""
    options: list[FieldOption] = field(default_factory=list)
    validations: list[ValidationRule] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "label": self.label,
            "type": self.field_type.value,
            "required": self.required,
            "default": self.default_value,
            "placeholder": self.placeholder,
            "help": self.help_text,
            "options": [opt.to_dict() for opt in self.options],
            "validations": [val.to_dict() for val in self.validations],
            "metadata": self.metadata
        }


@dataclass
class FormSection:
    """Group of related form fields."""

    name: str
    title: str
    description: str = ""
    fields: list[FormField] = field(default_factory=list)
    collapsible: bool = False
    collapsed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "fields": [f.to_dict() for f in self.fields],
            "collapsible": self.collapsible,
            "collapsed": self.collapsed
        }


@dataclass
class DynamicForm:
    """Complete dynamic form definition."""

    id: str
    title: str
    description: str = ""
    sections: list[FormSection] = field(default_factory=list)
    submit_label: str = "Submit"
    cancel_label: str = "Cancel"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "sections": [s.to_dict() for s in self.sections],
            "submit_label": self.submit_label,
            "cancel_label": self.cancel_label,
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class FormRenderer:
    """
    Generates dynamic forms from exploit metadata.

    Features:
    - Automatic form generation from exploit parameters
    - Field type inference
    - Validation rule creation
    - Multiple output formats (JSON, HTML, React)
    """

    def __init__(self):
        self.forms: dict[str, DynamicForm] = {}

    def generate_exploit_form(
        self,
        cve_id: str,
        include_common: bool = True
    ) -> DynamicForm:
        """
        Generate a form for an exploit module.

        Args:
            cve_id: CVE identifier
            include_common: Include common parameters (target, credentials, etc.)

        Returns:
            Generated DynamicForm
        """
        metadata = exploit_registry.get_metadata(cve_id)
        if not metadata:
            raise ValueError(f"Exploit {cve_id} not found")

        exploit_module = exploit_registry.get(cve_id)

        form = DynamicForm(
            id=f"form_{cve_id.lower().replace('-', '_')}",
            title=f"{metadata.name} Configuration",
            description=metadata.description,
            metadata={
                "cve_id": cve_id,
                "severity": metadata.severity,
                "requires_auth": metadata.requires_auth
            }
        )

        if include_common:
            target_section = self._create_target_section(metadata)
            form.sections.append(target_section)

        if hasattr(exploit_module, 'PARAMETERS') and exploit_module.PARAMETERS:
            exploit_section = self._create_exploit_section(
                exploit_module.PARAMETERS,
                metadata
            )
            form.sections.append(exploit_section)
        else:
            exploit_section = self._create_default_exploit_section(metadata)
            form.sections.append(exploit_section)

        options_section = self._create_options_section()
        form.sections.append(options_section)

        self.forms[cve_id] = form

        return form

    def _create_target_section(self, metadata: ExploitMetadata) -> FormSection:
        """Create target configuration section."""
        section = FormSection(
            name="target",
            title="Target Configuration",
            description="Configure the Jenkins target"
        )

        section.fields.append(FormField(
            name="target_url",
            label="Jenkins URL",
            field_type=FieldType.URL,
            required=True,
            placeholder="http://jenkins.example.com:8080",
            help_text="Full URL of the Jenkins server",
            validations=[
                ValidationRule(
                    type="pattern",
                    value="^https?://.*",
                    message="Must be a valid HTTP(S) URL"
                )
            ]
        ))

        if metadata.requires_auth:
            section.fields.append(FormField(
                name="username",
                label="Username",
                field_type=FieldType.TEXT,
                required=True,
                placeholder="admin",
                help_text="Jenkins username for authentication"
            ))

            section.fields.append(FormField(
                name="password",
                label="Password",
                field_type=FieldType.PASSWORD,
                required=True,
                help_text="Jenkins password for authentication"
            ))

        section.fields.append(FormField(
            name="proxy",
            label="Proxy (Optional)",
            field_type=FieldType.TEXT,
            required=False,
            placeholder="http://proxy:8080",
            help_text="HTTP proxy to use for connections"
        ))

        return section

    def _create_exploit_section(
        self,
        parameters: dict[str, Any],
        metadata: ExploitMetadata
    ) -> FormSection:
        """Create exploit-specific parameters section."""
        section = FormSection(
            name="exploit",
            title="Exploit Parameters",
            description=f"Configure parameters for {metadata.name}"
        )

        for param_name, param_config in parameters.items():
            field = self._parameter_to_field(param_name, param_config)
            section.fields.append(field)

        return section

    def _create_default_exploit_section(self, metadata: ExploitMetadata) -> FormSection:
        """Create default exploit section for modules without PARAMETERS."""
        section = FormSection(
            name="exploit",
            title="Exploit Parameters",
            description=f"Configure parameters for {metadata.name}"
        )

        if "rce" in metadata.tags or "code_execution" in metadata.tags:
            section.fields.append(FormField(
                name="command",
                label="Command",
                field_type=FieldType.TEXTAREA,
                required=True,
                placeholder="whoami",
                help_text="Command to execute on the target",
                default_value="whoami"
            ))

        if "reverse_shell" in metadata.tags:
            section.fields.append(FormField(
                name="lhost",
                label="Listener Host",
                field_type=FieldType.TEXT,
                required=True,
                placeholder="192.168.1.100",
                help_text="IP address for reverse connection"
            ))

            section.fields.append(FormField(
                name="lport",
                label="Listener Port",
                field_type=FieldType.NUMBER,
                required=True,
                default_value=4444,
                help_text="Port for reverse connection",
                validations=[
                    ValidationRule(
                        type="range",
                        value={"min": 1, "max": 65535},
                        message="Port must be between 1 and 65535"
                    )
                ]
            ))

        if "file_upload" in metadata.tags:
            section.fields.append(FormField(
                name="file_path",
                label="Remote File Path",
                field_type=FieldType.TEXT,
                required=True,
                placeholder="/tmp/payload.sh",
                help_text="Path where file will be uploaded"
            ))

        return section

    def _create_options_section(self) -> FormSection:
        """Create general options section."""
        section = FormSection(
            name="options",
            title="Execution Options",
            description="Configure how the exploit is executed",
            collapsible=True,
            collapsed=True
        )

        section.fields.append(FormField(
            name="timeout",
            label="Timeout (seconds)",
            field_type=FieldType.NUMBER,
            required=False,
            default_value=10,
            help_text="Request timeout in seconds",
            validations=[
                ValidationRule(
                    type="range",
                    value={"min": 1, "max": 300},
                    message="Timeout must be between 1 and 300 seconds"
                )
            ]
        ))

        section.fields.append(FormField(
            name="verify_ssl",
            label="Verify SSL Certificate",
            field_type=FieldType.BOOLEAN,
            required=False,
            default_value=False,
            help_text="Verify SSL certificate validity"
        ))

        section.fields.append(FormField(
            name="background",
            label="Run in Background",
            field_type=FieldType.BOOLEAN,
            required=False,
            default_value=False,
            help_text="Execute exploit as a background job"
        ))

        section.fields.append(FormField(
            name="delay",
            label="Delay (seconds)",
            field_type=FieldType.NUMBER,
            required=False,
            default_value=0,
            help_text="Delay before execution",
            validations=[
                ValidationRule(
                    type="range",
                    value={"min": 0, "max": 60},
                    message="Delay must be between 0 and 60 seconds"
                )
            ]
        ))

        return section

    def _parameter_to_field(self, name: str, config: dict[str, Any]) -> FormField:
        """Convert a parameter config to a FormField."""
        field_type = self._infer_field_type(config.get("type", "str"))

        field = FormField(
            name=name,
            label=config.get("label", name.replace("_", " ").title()),
            field_type=field_type,
            required=config.get("required", False),
            default_value=config.get("default"),
            placeholder=config.get("placeholder", ""),
            help_text=config.get("help", ""),
            metadata=config.get("metadata", {})
        )

        if "options" in config:
            field.options = [
                FieldOption(label=str(opt), value=opt)
                for opt in config["options"]
            ]

        if "min" in config or "max" in config:
            field.validations.append(ValidationRule(
                type="range",
                value={
                    "min": config.get("min"),
                    "max": config.get("max")
                },
                message=f"Value must be between {config.get('min')} and {config.get('max')}"
            ))

        if "pattern" in config:
            field.validations.append(ValidationRule(
                type="pattern",
                value=config["pattern"],
                message=config.get("pattern_message", "Invalid format")
            ))

        return field

    def _infer_field_type(self, type_str: str) -> FieldType:
        """Infer FieldType from type string."""
        type_mapping = {
            "str": FieldType.TEXT,
            "string": FieldType.TEXT,
            "int": FieldType.NUMBER,
            "integer": FieldType.NUMBER,
            "float": FieldType.NUMBER,
            "number": FieldType.NUMBER,
            "bool": FieldType.BOOLEAN,
            "boolean": FieldType.BOOLEAN,
            "password": FieldType.PASSWORD,
            "url": FieldType.URL,
            "email": FieldType.EMAIL,
            "text": FieldType.TEXTAREA,
            "file": FieldType.FILE,
            "select": FieldType.SELECT,
            "multiselect": FieldType.MULTISELECT
        }

        return type_mapping.get(type_str.lower(), FieldType.TEXT)

    def render_html(self, form: DynamicForm) -> str:
        """
        Render form as HTML.

        Args:
            form: Form to render

        Returns:
            HTML string
        """
        html = [f'<form id="{form.id}" class="dynamic-form">']
        html.append(f'  <h2>{form.title}</h2>')

        if form.description:
            html.append(f'  <p class="form-description">{form.description}</p>')

        for section in form.sections:
            html.append('  <fieldset class="form-section">')
            html.append(f'    <legend>{section.title}</legend>')

            if section.description:
                html.append(f'    <p class="section-description">{section.description}</p>')

            for field in section.fields:
                html.append(self._render_field_html(field))

            html.append('  </fieldset>')

        html.append('  <div class="form-actions">')
        html.append(f'    <button type="submit" class="btn-primary">{form.submit_label}</button>')
        html.append(f'    <button type="button" class="btn-secondary">{form.cancel_label}</button>')
        html.append('  </div>')
        html.append('</form>')

        return '\n'.join(html)

    def _render_field_html(self, field: FormField) -> str:
        """Render a single field as HTML."""
        required_attr = 'required' if field.required else ''

        html = ['    <div class="form-field">']
        html.append(f'      <label for="{field.name}">{field.label}')
        if field.required:
            html.append(' <span class="required">*</span>')
        html.append('</label>')

        if field.field_type == FieldType.TEXTAREA:
            html.append(f'      <textarea id="{field.name}" name="{field.name}" {required_attr} placeholder="{field.placeholder}">{field.default_value or ""}</textarea>')

        elif field.field_type == FieldType.BOOLEAN:
            checked = 'checked' if field.default_value else ''
            html.append(f'      <input type="checkbox" id="{field.name}" name="{field.name}" {checked}>')

        elif field.field_type == FieldType.SELECT:
            html.append(f'      <select id="{field.name}" name="{field.name}" {required_attr}>')
            for option in field.options:
                selected = 'selected' if option.value == field.default_value else ''
                html.append(f'        <option value="{option.value}" {selected}>{option.label}</option>')
            html.append('      </select>')

        else:
            input_type = field.field_type.value
            value = f'value="{field.default_value}"' if field.default_value else ''
            html.append(f'      <input type="{input_type}" id="{field.name}" name="{field.name}" {required_attr} {value} placeholder="{field.placeholder}">')

        if field.help_text:
            html.append(f'      <small class="help-text">{field.help_text}</small>')

        html.append('    </div>')

        return '\n'.join(html)

    def render_react(self, form: DynamicForm) -> str:
        """
        Render form as React component.

        Args:
            form: Form to render

        Returns:
            React JSX string
        """
        component_name = form.id.replace('_', ' ').title().replace(' ', '')

        jsx = [f'const {component_name} = () => {{']
        jsx.append('  const [formData, setFormData] = useState({')

        for section in form.sections:
            for field in section.fields:
                default = field.default_value
                if isinstance(default, str):
                    default = f'"{default}"'
                elif default is None:
                    default = '""'
                jsx.append(f'    {field.name}: {default},')

        jsx.append('  });')
        jsx.append('')
        jsx.append('  const handleChange = (e) => {')
        jsx.append('    const { name, value, type, checked } = e.target;')
        jsx.append('    setFormData(prev => ({')
        jsx.append('      ...prev,')
        jsx.append('      [name]: type === "checkbox" ? checked : value')
        jsx.append('    }));')
        jsx.append('  };')
        jsx.append('')
        jsx.append('  const handleSubmit = (e) => {')
        jsx.append('    e.preventDefault();')
        jsx.append('    console.log("Form submitted:", formData);')
        jsx.append('  };')
        jsx.append('')
        jsx.append('  return (')
        jsx.append('    <form onSubmit={handleSubmit} className="dynamic-form">')
        jsx.append(f'      <h2>{form.title}</h2>')

        for section in form.sections:
            jsx.append('      <fieldset>')
            jsx.append(f'        <legend>{section.title}</legend>')

            for field in section.fields:
                jsx.append(self._render_field_react(field))

            jsx.append('      </fieldset>')

        jsx.append('      <div className="form-actions">')
        jsx.append(f'        <button type="submit">{form.submit_label}</button>')
        jsx.append(f'        <button type="button">{form.cancel_label}</button>')
        jsx.append('      </div>')
        jsx.append('    </form>')
        jsx.append('  );')
        jsx.append('};')

        return '\n'.join(jsx)

    def _render_field_react(self, field: FormField) -> str:
        """Render a single field as React JSX."""
        jsx = ['        <div className="form-field">']
        jsx.append(f'          <label htmlFor="{field.name}">{field.label}</label>')

        if field.field_type == FieldType.TEXTAREA:
            jsx.append('          <textarea')
            jsx.append(f'            id="{field.name}"')
            jsx.append(f'            name="{field.name}"')
            jsx.append(f'            value={{formData.{field.name}}}')
            jsx.append('            onChange={handleChange}')
            jsx.append(f'            placeholder="{field.placeholder}"')
            if field.required:
                jsx.append('            required')
            jsx.append('          />')

        elif field.field_type == FieldType.BOOLEAN:
            jsx.append('          <input')
            jsx.append('            type="checkbox"')
            jsx.append(f'            id="{field.name}"')
            jsx.append(f'            name="{field.name}"')
            jsx.append(f'            checked={{formData.{field.name}}}')
            jsx.append('            onChange={handleChange}')
            jsx.append('          />')

        else:
            jsx.append('          <input')
            jsx.append(f'            type="{field.field_type.value}"')
            jsx.append(f'            id="{field.name}"')
            jsx.append(f'            name="{field.name}"')
            jsx.append(f'            value={{formData.{field.name}}}')
            jsx.append('            onChange={handleChange}')
            jsx.append(f'            placeholder="{field.placeholder}"')
            if field.required:
                jsx.append('            required')
            jsx.append('          />')

        if field.help_text:
            jsx.append(f'          <small>{field.help_text}</small>')

        jsx.append('        </div>')

        return '\n'.join(jsx)

    def get_form(self, form_id: str) -> Optional[DynamicForm]:
        """Get a generated form by ID."""
        return self.forms.get(form_id)

    def list_forms(self) -> list[str]:
        """List all generated form IDs."""
        return list(self.forms.keys())


def render_exploit_form(cve_id: str, format: str = "json") -> str:
    """
    Convenience function to render an exploit form.

    Args:
        cve_id: CVE identifier
        format: Output format (json, html, react)

    Returns:
        Rendered form
    """
    renderer = FormRenderer()
    form = renderer.generate_exploit_form(cve_id)

    if format == "json":
        return form.to_json()
    elif format == "html":
        return renderer.render_html(form)
    elif format == "react":
        return renderer.render_react(form)
    else:
        raise ValueError(f"Unsupported format: {format}")
