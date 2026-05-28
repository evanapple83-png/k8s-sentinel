"""ARGUS attack-graph engine v3 (CISO-grade).

  * ``engine.py``        — deterministic attack-graph correlation + SSVC scoring.
  * ``threat_intel.py``  — live CISA KEV + EPSS, with cache + override.
  * ``weights.json``     — calibratable scoring constants.
  * ``fixtures/``        — reference inventory + findings used by ``test_engine.py``
                           and by ``python -m argus.engine_v3.engine``.

Both modules support dual-import: they run both as scripts (``python
engine.py``) and as a package (``from argus.engine_v3 import engine``).
"""
from . import engine, threat_intel  # noqa: F401  (re-export for convenience)
