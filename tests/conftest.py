import datetime as dt
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

#: Every fixture is collected at this instant, so ages in assertions are fixed numbers.
AS_OF = dt.datetime(2026, 10, 20, 12, 0, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def fixture_path():
    def _path(name):
        return FIXTURES / name

    return _path


@pytest.fixture
def payload(fixture_path):
    from aws_secretsmanager_audit.model import Payload

    def _load(name):
        with open(fixture_path(name), "r", encoding="utf-8") as fh:
            return Payload(json.load(fh))

    return _load


@pytest.fixture
def rules_for(payload):
    """Map secret name -> set of rule names fired, for one fixture file."""
    from aws_secretsmanager_audit.rules import Options, audit

    def _run(name, **kwargs):
        findings = audit(payload(name), AS_OF, Options(**kwargs))
        out = {}
        for f in findings:
            out.setdefault(f.secret, set()).add(f.rule)
        return out

    return _run


@pytest.fixture
def findings_for(payload):
    from aws_secretsmanager_audit.rules import Options, audit

    def _run(name, **kwargs):
        return audit(payload(name), AS_OF, Options(**kwargs))

    return _run
