"""Polymorphic payload obfuscation engine.

Generates unique variations of Groovy payloads to evade signature-based
detection by randomizing variable names, code structure, and execution flow.
"""

import hashlib
import random
import string
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class ObfuscationResult:
    """Result of payload obfuscation."""
    obfuscated_code: str
    original_hash: str
    obfuscated_hash: str
    techniques_used: list[str]


class GroovyObfuscator:
    """Polymorphic Groovy payload obfuscator."""

    def __init__(self, seed: Optional[int] = None):
        """Initialize obfuscator.

        Args:
            seed: Random seed for reproducible obfuscation (testing only)
        """
        if seed is not None:
            random.seed(seed)

        self.techniques_used: list[str] = []

    def _generate_var_name(self, length: int = 12) -> str:
        """Generate random variable name.

        Args:
            length: Length of variable name

        Returns:
            Random variable name starting with letter
        """
        first = random.choice(string.ascii_lowercase)
        rest = ''.join(random.choices(string.ascii_letters + string.digits, k=length-1))
        return first + rest

    def _split_string(self, s: str) -> str:
        """Split string into random concatenations.

        Args:
            s: String to split

        Returns:
            Groovy code for concatenated string
        """
        if len(s) < 4:
            return f'"{s}"'

        chunks = []
        i = 0
        while i < len(s):
            chunk_size = random.randint(2, min(8, len(s) - i))
            chunks.append(s[i:i+chunk_size])
            i += chunk_size

        return ' + '.join(f'"{chunk}"' for chunk in chunks)

    def randomize_variable_names(self, code: str) -> str:
        """Randomize common variable names in code.

        Args:
            code: Groovy code to obfuscate

        Returns:
            Code with randomized variable names
        """
        common_vars = {
            'result': self._generate_var_name(),
            'output': self._generate_var_name(),
            'cmd': self._generate_var_name(),
            'command': self._generate_var_name(),
            'proc': self._generate_var_name(),
            'process': self._generate_var_name(),
            'data': self._generate_var_name(),
            'response': self._generate_var_name()
        }

        obfuscated = code
        for old_var, new_var in common_vars.items():
            obfuscated = obfuscated.replace(old_var, new_var)

        self.techniques_used.append("variable_randomization")
        return obfuscated

    def insert_junk_code(self, code: str) -> str:
        """Insert benign junk code between statements.

        Args:
            code: Groovy code

        Returns:
            Code with junk insertions
        """
        junk_patterns = [
            f"def {self._generate_var_name()} = {random.randint(1, 1000)}",
            f"// {self._generate_var_name()}",
            f"def {self._generate_var_name()} = '{self._generate_var_name()}'",
            f"if (false) {{ {self._generate_var_name()} = null }}"
        ]

        lines = code.split('\n')
        result_lines = []

        for line in lines:
            result_lines.append(line)
            if random.random() > 0.7 and line.strip() and not line.strip().startswith('//'):
                result_lines.append(random.choice(junk_patterns))

        self.techniques_used.append("junk_code_insertion")
        return '\n'.join(result_lines)

    def use_reflection(self, code: str) -> str:
        """Replace direct class references with reflection.

        Args:
            code: Groovy code

        Returns:
            Code using reflection for class loading
        """
        replacements = {
            'Runtime.getRuntime()': 'Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null)',
            'ProcessBuilder': 'Class.forName("java.lang.ProcessBuilder")',
            'new File(': 'Class.forName("java.io.File").getConstructor(String.class).newInstance(',
        }

        obfuscated = code
        for pattern, replacement in replacements.items():
            if pattern in obfuscated:
                obfuscated = obfuscated.replace(pattern, replacement)
                self.techniques_used.append("reflection_obfuscation")

        return obfuscated

    def encode_strings(self, code: str) -> str:
        """Encode string literals in code.

        Args:
            code: Groovy code

        Returns:
            Code with encoded strings
        """
        import re

        def encode_match(match):
            string_content = match.group(1)
            if len(string_content) < 3 or random.random() > 0.5:
                return match.group(0)

            if random.choice([True, False]):
                bytes_str = ', '.join(str(ord(c)) for c in string_content)
                return f'new String([{bytes_str}] as byte[])'
            else:
                hex_str = string_content.encode('utf-8').hex()
                return f'new String("{hex_str}".decodeHex())'

        pattern = r'"([^"]{3,})"'
        obfuscated = re.sub(pattern, encode_match, code)

        if obfuscated != code:
            self.techniques_used.append("string_encoding")

        return obfuscated

    def randomize_whitespace(self, code: str) -> str:
        """Randomize whitespace and formatting.

        Args:
            code: Groovy code

        Returns:
            Code with randomized whitespace
        """
        lines = code.split('\n')
        result_lines = []

        for line in lines:
            if line.strip():
                spaces = random.randint(0, 4)
                result_lines.append(' ' * spaces + line.strip())
            else:
                result_lines.append(line)

        self.techniques_used.append("whitespace_randomization")
        return '\n'.join(result_lines)

    def add_dead_branches(self, code: str) -> str:
        """Add dead code branches that never execute.

        Args:
            code: Groovy code

        Returns:
            Code with dead branches
        """
        dead_code = f"""
if ({random.randint(1,100)} > {random.randint(200, 300)}) {{
    def {self._generate_var_name()} = "{self._generate_var_name()}"
    {self._generate_var_name()}.toString()
}}
"""

        self.techniques_used.append("dead_code_branches")
        return dead_code + code

    def obfuscate(self,
                  code: str,
                  level: str = "moderate",
                  techniques: Optional[list[str]] = None) -> ObfuscationResult:
        """Apply obfuscation techniques to Groovy code.

        Args:
            code: Original Groovy code
            level: Obfuscation level (light, moderate, aggressive)
            techniques: Specific techniques to apply (None = auto-select based on level)

        Returns:
            ObfuscationResult with obfuscated code and metadata
        """
        self.techniques_used = []
        original_hash = hashlib.sha256(code.encode()).hexdigest()

        obfuscated = code

        if techniques is None:
            if level == "light":
                obfuscated = self.randomize_variable_names(obfuscated)
                obfuscated = self.randomize_whitespace(obfuscated)

            elif level == "moderate":
                obfuscated = self.randomize_variable_names(obfuscated)
                obfuscated = self.insert_junk_code(obfuscated)
                obfuscated = self.randomize_whitespace(obfuscated)
                obfuscated = self.add_dead_branches(obfuscated)

            elif level == "aggressive":
                obfuscated = self.randomize_variable_names(obfuscated)
                obfuscated = self.encode_strings(obfuscated)
                obfuscated = self.use_reflection(obfuscated)
                obfuscated = self.insert_junk_code(obfuscated)
                obfuscated = self.add_dead_branches(obfuscated)
                obfuscated = self.randomize_whitespace(obfuscated)
        else:
            technique_map: dict[str, Callable[[str], str]] = {
                "variable_randomization": self.randomize_variable_names,
                "junk_code_insertion": self.insert_junk_code,
                "reflection_obfuscation": self.use_reflection,
                "string_encoding": self.encode_strings,
                "whitespace_randomization": self.randomize_whitespace,
                "dead_code_branches": self.add_dead_branches
            }

            for technique in techniques:
                if technique in technique_map:
                    obfuscated = technique_map[technique](obfuscated)

        obfuscated_hash = hashlib.sha256(obfuscated.encode()).hexdigest()

        return ObfuscationResult(
            obfuscated_code=obfuscated,
            original_hash=original_hash,
            obfuscated_hash=obfuscated_hash,
            techniques_used=self.techniques_used.copy()
        )


class PayloadPolymorphism:
    """Generate multiple unique variants of the same payload."""

    def __init__(self):
        """Initialize polymorphism engine."""
        self.obfuscator = GroovyObfuscator()

    def generate_variants(self,
                         base_payload: str,
                         count: int = 5,
                         level: str = "moderate") -> list[ObfuscationResult]:
        """Generate multiple unique variants of a payload.

        Args:
            base_payload: Original payload code
            count: Number of variants to generate
            level: Obfuscation level

        Returns:
            List of ObfuscationResult objects
        """
        variants = []

        for _ in range(count):
            obfuscator = GroovyObfuscator()
            result = obfuscator.obfuscate(base_payload, level=level)
            variants.append(result)

        return variants

    def verify_uniqueness(self, variants: list[ObfuscationResult]) -> dict[str, Any]:
        """Verify that all variants have unique hashes.

        Args:
            variants: List of obfuscation results

        Returns:
            Dictionary with uniqueness statistics
        """
        hashes = [v.obfuscated_hash for v in variants]
        unique_hashes = set(hashes)

        return {
            "total_variants": len(variants),
            "unique_variants": len(unique_hashes),
            "uniqueness_rate": len(unique_hashes) / len(variants) if variants else 0,
            "collision_count": len(variants) - len(unique_hashes)
        }


def obfuscate_payload(code: str, level: str = "moderate") -> str:
    """Quick obfuscation helper.

    Args:
        code: Groovy code to obfuscate
        level: Obfuscation level (light, moderate, aggressive)

    Returns:
        Obfuscated code string
    """
    obfuscator = GroovyObfuscator()
    result = obfuscator.obfuscate(code, level=level)
    return result.obfuscated_code


def generate_polymorphic_variants(code: str, count: int = 5) -> list[str]:
    """Generate multiple unique variants of payload.

    Args:
        code: Base payload code
        count: Number of variants

    Returns:
        List of obfuscated payload strings
    """
    engine = PayloadPolymorphism()
    variants = engine.generate_variants(code, count=count)
    return [v.obfuscated_code for v in variants]
