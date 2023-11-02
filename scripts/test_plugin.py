"""!
@brief A test plugin to show how a new plugin can be created.
"""
from deject.plugins import Deject

#@Deject.plugin
def hash_something():
    """Function does nothing, this is just a docstr for demonstration purposes."""
    print("Hashing something")
    t = {"header": ["first", "second", "third"], "rows": [["a", "b", "c"], [1, 2, 3], [4, 5, 6]]}
    return t
