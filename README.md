# Purpose
The purpose of this script is to assist Snyk Administrators with updating Project test frequencies. This script allows the user to select a frequency and a desired affected project type (npm, nuget, etc).

# Prerequisites
- a Snyk token with Organization Administrator permissions
- Organization ID

# Installation
pip install -r requirements.txt

# Usage
python3 update_snyk.py 

# Options
--sca = Will update all SCA project types
--iac = Will update all IAC project types
--container = Will update all Container project types
--all-types = Will update all projects
