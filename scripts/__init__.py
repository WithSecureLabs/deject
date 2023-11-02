from deject import plugins

names = plugins.names_factory(__package__)
run = plugins.call_factory(__package__)
docs = plugins.doc_factory(__package__)