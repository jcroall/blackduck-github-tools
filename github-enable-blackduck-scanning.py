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

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                        description='Enable Black Duck scnaning on a GitHub repo')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--ghurl', default="https://api.github.com", help='GitHub Base URL')
parser.add_argument('--ghtoken', required=True, help='GitHub API Token')
parser.add_argument('--ghuser', required=True, help='GitHub User')
parser.add_argument('--localfile', required=True, help='Local file to upload')
parser.add_argument('--repo_slug', required=True, help='Repository in USER/REPO format')
parser.add_argument('--branch', required=True, help='Branch to use as intermediate branch')
parser.add_argument('--ghfilename', required=True, help='Remote filename on GitHub')
parser.add_argument('--bdtoken', required=True, help='Black Duck Token')
parser.add_argument('--bdurl', required=True, help='Black Duck URL')
args = parser.parse_args()

debug = int(args.debug)
ghurl = args.ghurl
ghtoken = args.ghtoken
ghuser = args.ghuser
localfile = args.localfile
repo_slug = args.repo_slug
branch = args.branch
ghfilename = args.ghfilename
bdtoken = args.bdtoken
bdurl = args.bdurl

g = Github(ghtoken, base_url=ghurl)

# Connect to repository
repo = g.get_repo(repo_slug)
#repo = g.get_user().get_repo(repo_slug)
if (debug):
    print(f"DEBUG: Connected to repository {repo_slug}")
    print(repo)

#branches = repo.get_branches()
#if (debug):
#    print("DEBUG: Fetched existing branches")
#    list(branches)

# Create secrets
repo.create_secret("BLACKDUCK_TOKEN", bdtoken)
repo.create_secret("BLACKDUCK_URL", bdurl)

# Create branch
commit = repo.get_commit('HEAD')
if (debug):
    print(f"DEBUG: Got HEAD commit from {repo_slug}")
    print(commit)

print(f"INFO: Creating branch {branch} in repo {repo_slug}")
ref = repo.create_git_ref("refs/heads/" + branch, commit.sha)
if (debug):
    print(f"DEBUG: Created refs/heads/{branch} against commit {commit.sha}")
    print(ref)

# Upload file
print(f"INFO: Uploading file '{localfile}' to '{ghfilename}'")
fp = open(localfile, mode='r')
file_contents = fp.read()
fp.close()

file = repo.create_file(ghfilename, "Enable Synopsys Black Duck", file_contents, branch=branch)
if (debug):
    print(f"DEBUG: Uploaded file in new commit")
    print(file)

# Submit pull request
body = '''
SUMMARY
Enable Synopsys Black Duck scanning by adding a new workflow configuration.

'''
print(f"INFO: Create merge request to submit change, please merge to enable Black Duck")
pr = repo.create_pull(title="Enable Synopsys Black Duck scanning", body=body, head=branch, base="master")
if (debug):
    print(f"DEBUG: Created pull request")
    print(pr)

print(f"INFO: Successfully created temporary branch {branch}, committed {localfile} in order to enable Black Duck scanning, and submitted pull request")
# TODO: Can we force a delete on merge?
#print(f"INFO: Please accept the pull request and on merge the temporary branch {branch} will be deleted")

# for un-on-boarding:
# >>> repo = g.get_repo("PyGithub/PyGithub")
# >>> contents = repo.get_contents("test.txt", ref="test")
# >>> repo.delete_file(contents.path, "remove test", contents.sha, branch="test")
