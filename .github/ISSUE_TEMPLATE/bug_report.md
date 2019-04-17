---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**Affected module**
Which one is the module that is not working as expected, e.g. Nessus, Qualys WAS, Qualys VM, OpenVAS, ELK, Jira...). 

**VulnWhisperer debug trail**
If applicable, paste the VulnWhisperer debug trail of the execution for further detail (execute with '-d' flag).

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**System in which VulnWhisperer runs (please complete the following information):**
 - OS: [e.g. Ubuntu Server]
 - Version: [e.g. 18.04.2 LTS]
 - VulnWhisperer Version: [e.g. 1.7.1]

**Additional context**
Add any other context about the problem here.

## Important Note
As VulnWhisperer relies on ELK for the data aggregation, it is expected that you already have an ELK instance or the knowledge to deploy one. 
In order to speed up deployment, we provide an updated and tested docker-compose file which deploys all the needed infrastructure and we will support its deployment, but we will not be giving support to ELK instances.
