import sys
import base64
import requests
import hashlib
import json
import datetime
import argparse

import requests
import base64
import json
import datetime

from github import Github

def userexists(username, ghurl):
    addr = ghurl + "/users/" + username
    response = requests.get(addr)
    if response.status_code == 404:
        return False
    else:
        if response.status_code == 200:
            return True

def printrepos(repos):
    original_repos = []
    for repo in repos:
        if repo.fork is False and repo.archived is False:
            print(repo.clone_url)

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                        description='List GitHub Repos')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--ghurl', default="https://api.github.com", help='GitHub Base URL')
parser.add_argument('--ghtoken', required=True, help='GitHub API Token')
parser.add_argument('--ghuser', required=True, help='GitHub User or Organization')
parser.add_argument('--noforks', default=False, action='store_true', help='Do not include forks')
args = parser.parse_args()

debug = int(args.debug)
ghurl = args.ghurl
ghtoken = args.ghtoken
ghuser = args.ghuser

g = Github(ghtoken, base_url=ghurl)

if userexists(ghuser, ghurl):
    user = g.get_user(ghuser)
    repos = user.get_repos()
    printrepos(repos)
else:
    print("Username doesn't exist")
