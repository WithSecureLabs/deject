"""! @brief This plugin is used to get behaviour from the Virus Total sandbox. To run the plugin, type
poetry run deject run --include agenttesla_behaviour \<file\>. This plugin has no arguments and needs the
VT_KEY environment variable set."""

from deject.plugins import Deject
import scripts.helpers as utils
import hashlib
from typer import secho,colors


## Data to extract from the SMTP fields
INTERESTING_SMTP_DATA = ['smtp_from', 'smtp_to', 'subject']

@Deject.plugin
def agenttesla():
    """Get AgentTesla behaviour"""
    filename = Deject.file_path
    with open(filename, "rb") as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    secho(f"SHA1: {sha1}")
    extract_interesting_information(sha256,filename)

def extract_interesting_information(hash, filename):
    """Retrieves Virus Total sandbox information for a given file."""
    vt_key = utils.Settings().getSetting("vt_key")
    if vt_key == "":
        secho("VT API key is unset, please set VT_KEY environment variable to use this plugin.", fg=colors.RED)
    else:
        vt = utils.virustotal(vt_key)
        report = vt.getBehavior(hash)
        result = {}
        c2s = []
        injected_processes = []
        registry_keys = []
        file_writes = []
        services_started = []

        for sandbox in report:
            if attributes := sandbox.get('attributes'):
                if services := attributes.get('services_started'):
                    services_started.extend(services)
                    
                if smtp_conversations := attributes.get('smtp_conversations'):
                    for conversation in smtp_conversations:
                        c2_conversation = {}
                        c2_conversation['c2_type'] = 'smtp'
                        c2_conversation['data'] = {
                            key: conversation.get(key, f'no {key}') for key in INTERESTING_SMTP_DATA
                        }
                        c2s.append(c2_conversation)

                if http_conversations := attributes.get('http_conversations'):
                    for conversation in http_conversations:
                        c2_conversation = {}
                        if 'telegram' in conversation['url'].lower():
                            c2_conversation['c2_type'] = 'telegram'
                        if c2_conversation.get('response_status_code'):
                            c2_conversation['data'] = {
                                'url': conversation['url'],
                                'request_method': conversation['request_method'],
                                'status_code': conversation['response_status_code']
                            }
                        else:
                            c2_conversation['data'] = {
                                'url': conversation['url'],
                                'request_method': conversation['request_method'],
                            }
                        c2s.append(c2_conversation)
                if ip_traffic := attributes.get('ip_traffic'):
                    for ip in ip_traffic:
                        c2_conversation = {}
                        c2_conversation['c2_type'] = ip['transport_layer_protocol']                
                        c2_conversation['data'] = {
                                'destination': ip['destination_ip'],
                                'port': ip['destination_port']
                        }
                        c2s.append(c2_conversation)

                if processes_injected := attributes.get('processes_injected'):
                    injected_processes.extend(processes_injected)
                if registry_keys_set := attributes.get('registry_keys_set'):
                    registry_keys.extend(registry_keys_set)
                if files_written := attributes.get('files_dropped'):
                    file_writes.extend(files_written)

        if len(c2s) > 0:
            result['c2_conversations'] = c2s
        if len(injected_processes) > 0:
            result['injected_processes'] = injected_processes
        if len(registry_keys) > 0:
            result['registry_keys_written'] = registry_keys
        if len(file_writes) > 0:
            result['files_written'] = file_writes
        if len(services_started) > 0:
            result['services_started'] = set(services_started)

        if result:
            secho(result,fg=colors.GREEN)
        # parsing failed
        else: 
            secho(f"No information found for {filename}", fg=colors.RED)

def help():
    print("""
Agent Tesla Plugin
SYNOPSIS <filename>
This plugin is used to get behaviour from the Virus Total sandbox. To run the plugin, type
poetry run deject run --include agenttesla_behaviour <file>. This plugin has no arguments and needs the
VT_KEY environment variable set with a VT API key.
""")