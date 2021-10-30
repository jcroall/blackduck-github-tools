import sys
import platform
import subprocess
import os
import requests
import argparse
import json
import glob
import hashlib
import zipfile
from zipfile import ZIP_DEFLATED
from pprint import pprint

import networkx as nx
import matplotlib.pyplot as plt

from blackduck import Client

def line_num_for_phrase_in_file(phrase, filename):
    with open(filename,'r') as f:
        for (i, line) in enumerate(f):
            if phrase.lower() in line.lower():
                return i
    return -1

def get_package_file(bd, component_identifier, component_name):
    ptype = component_identifier.split(':')[0]
    name_version = component_identifier.split(':')[1]
    name = name_version.split('/')[0]
    # TODO: Is component_name the right thing to search for?
    if (ptype == 'npmjs'):
        if (line_num_for_phrase_in_file("\"" + name + "\"", "package.json") > 0):
            return "package.json"
        if (line_num_for_phrase_in_file("\"" + name + "\"", "package-lock.json") > 0):
            return "package-lock.json"
    elif (ptype == 'maven'):
        if (line_num_for_phrase_in_file(name, "pom.xml") > 0):
            return "pom.xml"
    # TODO: Add support for NuGet
    #elif (ptype == 'nuget'):
    #    What to do?
    else:
        return "Unknown"

    return "Unknown"

def read_json_object(filepath):
    with open(filepath) as jsonfile:
        data = json.load(jsonfile)
        return data

def zip_extract_files(zip_file, dir_name):
    print("Extracting content of {} into {}".format(zip_file, dir_name))
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(dir_name)

def bdio_read(bdio_in, inputdir):
    zip_extract_files(bdio_in, inputdir)
    filelist = os.listdir(inputdir)
    for filename in filelist:
        #print ("processing {}".format(filename))
        filepath_in = os.path.join(inputdir, filename)
        data = read_json_object(filepath_in)
        return data

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                description='Generate GitHub SARIF file from Black Duck Rapid Scan')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--apitoken', required=True, help='Black Duck API Token')
parser.add_argument('--url', required=True, help='Black Duck Base URL')
parser.add_argument('--output_directory', required=True, help='Rapid Scan output directory')
parser.add_argument('--output', required=True, help='File to output SARIF to')
args = parser.parse_args()

debug = int(args.debug)
bd_apitoken = args.apitoken
bd_url = args.url
bd_rapid_output_dir = args.output_directory
sarif_output_file = args.output

bd = Client(token=bd_apitoken,
        base_url=bd_url,
        timeout=300)

# Parse BDIO file into network graph
#bd_rapid_output_bdio_glob = glob.glob(bd_rapid_output_dir + "/runs/*/bdio/*.bdio")
#if (len(bd_rapid_output_bdio_glob) == 0):
#    print("ERORR: Unable to find output scan files in: " + bd_rapid_output_dir + "/runs/*/bdio/*.bdio")
#    sys.exit(1)
#
#bd_rapid_output_bdio = bd_rapid_output_bdio_glob[0]
#
#bd_rapid_output_bdio_dir = glob.glob(bd_rapid_output_dir + "/runs/*/bdio")[0]
#bdio_data = bdio_read(bd_rapid_output_bdio, bd_rapid_output_bdio_dir)
#if (debug):
#    print(f"DEBUG: BDIO Dump: "+ json.dumps(bdio_data, indent=4))
#
## Construct dependency graph
#G = nx.DiGraph()
##G.add_edges_from(
##            [('project', 'express-handlebars'), ('project', 'nodemailer'), ('express-handlebars', 'anotherone'), ('express-handlebars', 'handlebars')])
#
#if (debug): print("DEBUG: Create dependency graph...")
#for node in bdio_data['@graph']:
#    parent = node['@id']
#    G.add_edge("Project", parent)
#    if (debug): print(f"DEBUG: Parent {parent}")
#    if "https://blackducksoftware.github.io/bdio#hasDependency" in node:
#        if (isinstance(node['https://blackducksoftware.github.io/bdio#hasDependency'], list)):
#            for dependency in node['https://blackducksoftware.github.io/bdio#hasDependency']:
#                child = dependency['https://blackducksoftware.github.io/bdio#dependsOn']['@id']
#                if (debug): print(f"DEBUG:   Dependency on {child}")
#                G.add_edge(parent, child)
#        else:
#            child = dependency['https://blackducksoftware.github.io/bdio#dependsOn']['@id']
#            if (debug): print(f"DEBUG:   Dependency on {child}")
#            G.add_edge(parent, child)
#
#if (debug):
#    map = nx.to_dict_of_dicts(G)
#    print(f"DEBUG: Dump graph")
#    print(json.dumps(map, indent=4))
#
#    #nx.draw(G)
#    #plt.savefig("filename.png")
#
#    an = nx.ancestors(G, "http:npmjs/commander/2.20.3")
#    print("DEBUG: Ancestors:")
#    print(an)
#
#    paths = nx.all_simple_paths(G, source="Project", target="http:npmjs/commander/2.20.3")
#    print("DEBUG: Paths to 'http:npmjs/commander/2.20.3'")
#    for path in paths:
#        print(path)
#
#sys.exit(1)

# Parse the Rapid Scan output, assuming there is only one run in the directory
bd_rapid_output_file_glob = glob.glob(bd_rapid_output_dir + "/runs/*/scan/*.json")
if (len(bd_rapid_output_file_glob) == 0):
    print("ERORR: Unable to find output scan files in: " + bd_rapid_output_dir + "/runs/*/scan/*.json")
    sys.exit(1)

bd_rapid_output_file = bd_rapid_output_file_glob[0]
print("INFO: Parsing Black Duck Rapid Scan output from " + bd_rapid_output_file)
with open(bd_rapid_output_file) as f:
    output_data = json.load(f)

developer_scan_url = output_data[0]['_meta']['href']
if (debug): print("DEBUG: Developer scan href: " + developer_scan_url)

# Handle limited lifetime of developer runs gracefully
try:
    dev_scan_data = bd.get_json(developer_scan_url)
except:
    print(f"ERROR: Unable to fetch developer scan '{developer_scan_url}' - note that these are limited lifetime and this process must run immediately following the rapid scan")
    raise

# TODO: Handle error if can't read file
if (debug): print("DEBUG: Developer scan data: " + json.dumps(dev_scan_data, indent=4) + "\n")

# Prepare SARIF output structures
runs = []
run = dict()

component_match_types = dict()
components = dict()

tool_rules = []
results = []

for item in dev_scan_data['items']:
    if (debug): print(f"DEBUG: Component: {item['componentIdentifier']}")
    # Get component upgrade advice
    if (debug): print(f"DEBUG: Search for component '{item['componentIdentifier']}'")
    params = {
            'q': [ item['componentIdentifier'] ]
            }
    search_results = bd.get_items('/api/components', params=params)
    # There should be exactly one result!
    # TODO: Error checking?
    for result in search_results:
        component_result = result
    if (debug): print("DEBUG: Component search result=" + json.dumps(component_result, indent=4) + "\n")

    # Get component upgrade data
    if (debug): print(f"DBEUG: Looking up upgrade guidance for component '{component_result['componentName']}'")
    component_upgrade_data = bd.get_json(component_result['version'] + "/upgrade-guidance")
    if (debug): print("DEBUG: Compponent upgrade data=" + json.dumps(component_upgrade_data, indent=4) + "\n")

    upgrade_version = component_upgrade_data['longTerm']['versionName']

    # TODO: Process BDIO file from blackduck output directory to build
    # dependency graph, use NetworkX for Python, locate package node and
    # then use networkx.DiGraph.predecessors to access parents.
    #
    # Use hub-rest-api-python/examples/bdio_update_project_name.py as
    # a reference.

    package_file = get_package_file(bd, item['componentIdentifier'], item['componentName'])

    # Loop through polciy violations and append to SARIF output data
    for vuln in item['policyViolationVulnerabilities']:
        print(f"INFO: {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': {vuln['description']} Recommended to upgrade to version {upgrade_version}. Fix in package file '{package_file}'.")

        result = dict()
        result['ruleId'] = vuln['name']
        message = dict()
        message['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {component_result['componentName']}."
        result['message'] = message
        locations = []
        loc = dict()
        loc['file'] = package_file
        # TODO: Can we reference the line number in the future, using project inspector?
        loc['line'] = 1

        tool_rule = dict()
        tool_rule['id'] = vuln['name']
        shortDescription = dict()
        shortDescription['text'] = f"{vuln['name']} - {vuln['vulnSeverity']} severity vulnerability in {component_result['componentName']}"
        tool_rule['shortDescription'] = shortDescription
        fullDescription = dict()
        fullDescription['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {component_result['componentName']}"
        tool_rule['fullDescription'] = fullDescription
        rule_help = dict()
        rule_help['text'] = ""
        rule_help['markdown'] = f"*{vuln['description']} Recommended to upgrade to version {upgrade_version}. Fix in package file '{package_file}'*"
        tool_rule['help'] = rule_help
        defaultConfiguration = dict()

        if (vuln['vulnSeverity'] == "CRITITAL" or vuln['vulnSeverity'] == "HIGH"):
            defaultConfiguration['level'] = "error"
        elif (vuln['vulnSeverity'] == "MEDIUM"):
            efaultConfiguration['level'] = "warning"
        else:
            defaultConfiguration['level'] = "note"

        tool_rule['defaultConfiguration'] = defaultConfiguration
        properties = dict()
        properties['tags'] = []
        tool_rule['properties'] = properties
        tool_rules.append(tool_rule)

        location = dict()
        physicalLocation = dict()
        artifactLocation = dict()
        artifactLocation['uri'] = loc['file']
        physicalLocation['artifactLocation'] = artifactLocation
        region = dict()
        region['startLine'] = loc['line']
        physicalLocation['region'] = region
        location['physicalLocation'] = physicalLocation
        locations.append(location)
        result['locations'] = locations

        # Calculate fingerprint using simply the CVE/BDSA - the scope is the project in GitHub, so this should be fairly accurate for identifying a unique issue.
        # Guidance from https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#preventing-duplicate-alerts-using-fingerprints
        # and https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012611
        partialFingerprints = dict()
        primaryLocationLineHash = hashlib.sha224(b"{vuln['name']}").hexdigest()
        partialFingerprints['primaryLocationLineHash'] = primaryLocationLineHash
        result['partialFingerprints'] = partialFingerprints

        print("RESULTS ADD")
        results.append(result)

run['results'] = results
print("RESULTS SIZE: ")
print(len(results))
runs.append(run)

tool = dict()
driver = dict()
driver['name'] = "Synopsys Black Duck"
driver['organization'] = "Synopsys"
driver['rules'] = tool_rules
tool['driver'] = driver
run['tool'] = tool

code_security_scan_report = dict()
code_security_scan_report['runs'] = runs
code_security_scan_report['$schema'] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
code_security_scan_report['version'] = "2.1.0"
code_security_scan_report['runs'] = runs

if (debug):
    print("DEBUG: SARIF Data structure=" + json.dumps(code_security_scan_report, indent=4))
with open(sarif_output_file, "w") as fp:
    json.dump(code_security_scan_report, fp, indent=4)

# For debugging one by one
#sys.exit(1)

print("Done")
