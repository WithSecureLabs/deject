import pytest
import deject.main

def test_yarascan():
    assert deject.main.run("tests/data/hello","","","",["*"],["yarascan"],"") == 0
