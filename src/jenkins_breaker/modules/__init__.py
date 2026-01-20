"""
JenkinsBreaker exploit modules.

All CVE exploit modules and feature-based exploitation modules implementing
the ExploitModule interface.
"""

from jenkins_breaker.modules.base import (
    ExploitMetadata,
    ExploitModule,
    ExploitResult,
    exploit_registry,
)
from jenkins_breaker.modules.cve_2016_0792 import CVE_2016_0792
from jenkins_breaker.modules.cve_2017_1000353 import CVE_2017_1000353
from jenkins_breaker.modules.cve_2018_1000402 import CVE_2018_1000402
from jenkins_breaker.modules.cve_2018_1000600 import CVE_2018_1000600
from jenkins_breaker.modules.cve_2018_1000861 import CVE_2018_1000861
from jenkins_breaker.modules.cve_2019_10358 import CVE_2019_10358
from jenkins_breaker.modules.cve_2019_1003000 import CVE_2019_1003000
from jenkins_breaker.modules.cve_2019_1003001 import CVE_2019_1003001
from jenkins_breaker.modules.cve_2019_1003029 import CVE_2019_1003029
from jenkins_breaker.modules.cve_2019_1003040 import CVE_2019_1003040
from jenkins_breaker.modules.cve_2020_2100 import CVE_2020_2100
from jenkins_breaker.modules.cve_2020_2249 import CVE_2020_2249
from jenkins_breaker.modules.cve_2021_21602 import CVE_2021_21602
from jenkins_breaker.modules.cve_2021_21686 import CVE_2021_21686
from jenkins_breaker.modules.cve_2022_30945 import CVE_2022_30945
from jenkins_breaker.modules.cve_2022_34177 import CVE_2022_34177
from jenkins_breaker.modules.cve_2022_43401 import CVE_2022_43401
from jenkins_breaker.modules.cve_2023_3519 import CVE_2023_3519
from jenkins_breaker.modules.cve_2023_24422 import CVE_2023_24422
from jenkins_breaker.modules.cve_2023_27903 import CVE_2023_27903
from jenkins_breaker.modules.cve_2024_23897 import CVE_2024_23897
from jenkins_breaker.modules.cve_2024_34144 import CVE_2024_34144
from jenkins_breaker.modules.cve_2024_43044 import CVE_2024_43044
from jenkins_breaker.modules.cve_2024_47803 import CVE_2024_47803
from jenkins_breaker.modules.cve_2025_31722 import CVE_2025_31722
from jenkins_breaker.modules.feature_job_config import FeatureJobConfig
from jenkins_breaker.modules.feature_script_console import FeatureScriptConsole

exploit_registry.register(CVE_2016_0792)
exploit_registry.register(CVE_2017_1000353)
exploit_registry.register(CVE_2018_1000402)
exploit_registry.register(CVE_2018_1000600)
exploit_registry.register(CVE_2018_1000861)
exploit_registry.register(CVE_2019_1003000)
exploit_registry.register(CVE_2019_1003001)
exploit_registry.register(CVE_2019_1003029)
exploit_registry.register(CVE_2019_1003040)
exploit_registry.register(CVE_2019_10358)
exploit_registry.register(CVE_2020_2100)
exploit_registry.register(CVE_2020_2249)
exploit_registry.register(CVE_2021_21602)
exploit_registry.register(CVE_2021_21686)
exploit_registry.register(CVE_2022_30945)
exploit_registry.register(CVE_2022_34177)
exploit_registry.register(CVE_2022_43401)
exploit_registry.register(CVE_2023_3519)
exploit_registry.register(CVE_2023_24422)
exploit_registry.register(CVE_2023_27903)
exploit_registry.register(CVE_2024_23897)
exploit_registry.register(CVE_2024_34144)
exploit_registry.register(CVE_2024_43044)
exploit_registry.register(CVE_2024_47803)
exploit_registry.register(CVE_2025_31722)
exploit_registry.register(FeatureScriptConsole)
exploit_registry.register(FeatureJobConfig)


__all__ = [
    "ExploitModule",
    "ExploitMetadata",
    "ExploitResult",
    "exploit_registry",
    "CVE_2016_0792",
    "CVE_2017_1000353",
    "CVE_2018_1000402",
    "CVE_2018_1000600",
    "CVE_2018_1000861",
    "CVE_2019_1003000",
    "CVE_2019_1003001",
    "CVE_2019_1003029",
    "CVE_2019_1003040",
    "CVE_2019_10358",
    "CVE_2020_2100",
    "CVE_2020_2249",
    "CVE_2021_21602",
    "CVE_2021_21686",
    "CVE_2022_30945",
    "CVE_2022_34177",
    "CVE_2022_43401",
    "CVE_2023_3519",
    "CVE_2023_24422",
    "CVE_2023_27903",
    "CVE_2024_23897",
    "CVE_2024_34144",
    "CVE_2024_43044",
    "CVE_2024_47803",
    "CVE_2025_31722",
    "FeatureScriptConsole",
    "FeatureJobConfig",
]
