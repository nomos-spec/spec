#!/usr/bin/env python3
"""NOMOS-SPEC-008 0.6.0 reference verifier: Act Binding.

The verifier is `nomosprotocol.act` (python/nomosprotocol/act.py), the same code the published
`nomosprotocol` package ships. This file keeps the name the vector scripts and the
specification refer to.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomosprotocol.act import *  # noqa: E402,F401,F403
from nomosprotocol.act import _jcs  # noqa: E402,F401
