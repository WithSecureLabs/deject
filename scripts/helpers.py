"""!
@brief This file contains helper classes and functions.
@details If a function is used for multiple plugins, it
might be best to add it here for easier maintenance.
"""


class helpers:
    """!
    @brief Helper class for helper functions.
    """
    import yara
    import subprocess

    def yara_exec(self, rule, fi):
        """! @brief run Yara on files
        @param[in] rule Rule File
        @param[in] fi Filename"""

        rules_file = open(rule, "r")

        yara_data = open(fi, "rb")

        rule = self.yara.compile(source=rules_file.read())
        matches = rule.match(data=yara_data.read())

        rules_file.close()
        yara_data.close()

        return matches

    def script_exec(self, script, filename, arg):
        """! @brief run a python script file on a file
        @details runs subprocess.call([python3, script, arg, filename])
        @param[in] script Script file
        @param[in] filename File to pass to script
        @param[in] arg Arguments to the script (optional)"""
        if len(arg) > 0:
            self.subprocess.call(["python3", script, arg, filename])
        else:
            self.subprocess.call(["python3", script, filename])

    def bin_exec(self, process):
        """! @brief run a program on a file
        @details runs subprocess.call(process) after building the process list in the plugin
        @param[in] process Process list for a subprocess.call()"""
        self.subprocess.call(process)

    def get_rules(self, config_dir):
        """! @brief collect yara rules from a directory
        @param[in] config_dir rules repo"""
        rules = []
        scripts = []
        for f in config_dir.rglob("*"):
            if f.suffix == ".yara" or f.suffix == ".yar":
                rules.append(str(f))
            if f.suffix == ".py":
                scripts.append(str(f))
        return rules, scripts


class Settings:
    """!
    @brief Setting class to read the settings.yml file.
    """
    import yaml
    import os
    import sys
    import logging

    settings_file = "settings.yml"

    def __init__(self) -> None:
        self.cfg = {}
        self.logger = self.logging.getLogger(__class__.__name__)

        with open(self.settings_file, "r") as ymlfile:
            try:
                configuration = self.yaml.load(
                    ymlfile, Loader=self.yaml.FullLoader,
                )
                for item, conf in configuration.items():
                    self.cfg[item] = conf
            except IOError:
                self.logger.error(
                    f"Could not open {self.settings_file}",
                )
                self.sys.exit(1)

        for key in self.cfg["env_variables"]:
            try:
                self.cfg[key] = self.os.environ[self.cfg["env_variables"][key]]
            except:
                self.cfg[key] = ""

        self._cfg = self.cfg

    def getSetting(self, setting):
        return self.cfg[setting]

    def getIndex(self, indexname):
        return self._indices[indexname]

    def getEnvVariable(self, varname):
        try:
            return self._envvariables[varname]
        except KeyError:
            self.logger.error(
                f"Env Variable does not exist: {varname}",
            )
            return None


class virustotal:
    """!
    @brief Virus Total class to handle Virus Total API calls.
    """
    # VT Interactions
    import logging
    import requests
    import json

    settings = Settings()
    DOWNLOAD_URL = "https://www.virustotal.com/api/v3/files/"
    MATCHES = {}

    def __init__(self, VT_KEY):
        self.VT_KEY = VT_KEY
        self.logger = self.logging.getLogger(__class__.__name__)

    def getBehavior(self, hash):
        behavior_lookup = self.requests.get(
            self.DOWNLOAD_URL + hash + "/behaviours",
            headers={"x-apikey": self.VT_KEY},
        )
        if str(behavior_lookup.status_code) != "200":
            self.logger.error(
                f"VT API Behaviour lookup Status code was non-200: {behavior_lookup.status_code} - {behavior_lookup.reason}",
            )
            return {}
        behavior_data = self.json.loads(behavior_lookup.content)["data"]
        return behavior_data
