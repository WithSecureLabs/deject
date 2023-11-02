import pytest
import deject.main

def test_help():
    for script in deject.main.scripts.names():
        assert deject.main.help(script) == 0
