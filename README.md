# NSX-Reset-Environment
A script to remove various objects from an NSX-v installation.

##Prerequisites
Requires the Requests libraby to be installed. Requests can be downloaded a from the following URL
http://docs.python-requests.org/en/latest/

##Usage
###Help
```
python nsx-reset-environment.py -h
```
Output:
```
python nsx-reset-environment.py -h
usage: nsx-reset-environment.py [-h] --nsxmgr nsxmgr [--user [user]]
                                [--ipsets] [--services] [--secgroups]
                                [--servicegroups] [--macsets] [--secpolicies]
                                [--sectags] [--fwrules]

Bulk delete NSX Objects.

optional arguments:
  -h, --help       show this help message and exit
  --nsxmgr nsxmgr  NSX Manager hostname, FQDN or IP address
  --user [user]    OPTIONAL - NSX Manager username (default: admin)
  --ipsets         Delete all IP Sets
  --services       Delete all services
  --secgroups      Delete all security groups
  --servicegroups  Delete all service groups
  --macsets        Delete all MAC sets
  --secpolicies    Delete all security policies
  --sectags        Delete all security tags
  --fwrules        Delete all firewall rules and reset to default
```
##Examples
###Deleting IP Sets
This will delete all IP Sets configured in NSX-v except all hidden/system required objects.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --ipsets
NSX Manager password:

SUCCESS: Retrieved list of IP Sets in scope | globalroot-0
INFO: Skipping Read Only IP Set ipset-1
```
###Deleting Services
WARNING: This will delete ALL NSX-v services Including ALL pre-configured services included in a default installation.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --services
NSX Manager password:

SUCCESS: Retrieved list of Services in scope | globalroot-0
INFO: Deleting Service: application-2
```
###Deleting Security Groups
This will delete all security groups configured in NSX-v except all the hidden/system required objects.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --secgroups
NSX Manager password:

SUCCESS: Retrieved list of Security Groups in scope | globalroot-0
INFO: Skipping Security Group "Activity Monitoring Data Collection" (securitygroup-1)
```
###Deleting Service Groups
WARNING: This will delete ALL NSX-v service groups Including ALL pre-configured services included in a default installation.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --servicegroups
NSX Manager password:

SUCCESS: Retrieved list of Service Groups in scope | globalroot-0
INFO: Deleting Service Group: applicationgroup-1
```
###Deleting MAC Sets
This will delete all MAC Sets configured in NSX-v except all the hidden/system required objects.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --macsets
NSX Manager password:

SUCCESS: Retrieved list of MAC Sets in scope | globalroot-0
INFO: Skipping Read Only MAC Set macset-1
INFO: Skipping Hidden MAC Set macset-1
INFO: Skipping Facade Hidden MAC Set macset-1
INFO: Deleting MAC Set macset-2
```
###Deleting Security Policies (Service Composer)
This will delete all Service Composer Security Policies configured in NSX-v except all the hidden/system required objects.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --secpolicies
NSX Manager password:

SUCCESS: Retrieved list of Security Policies
INFO: Deleting security policy policy-5
INFO: Skipping hidden security policy policy-4
INFO: Skipping hidden security policy policy-3
INFO: Skipping hidden security policy policy-2
INFO: Skipping hidden security policy policy-1
```
###Deleting Security Tags
This will delete all Security Tags configured in NSX-v except all the hidden/system required objects.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --sectags
NSX Manager password:

SUCCESS: Retrieved list of Security Tags
INFO: Skipping system security tag securitytag-1
INFO: Skipping system security tag securitytag-2
INFO: Skipping system security tag securitytag-3
INFO: Skipping system security tag securitytag-4
INFO: Skipping system security tag securitytag-5
INFO: Skipping system security tag securitytag-6
INFO: Skipping system security tag securitytag-7
INFO: Skipping system security tag securitytag-8
INFO: Skipping system security tag securitytag-9
INFO: Skipping system security tag securitytag-10
INFO: Skipping system security tag securitytag-11
```
###Deleting Firewall Rules
This will delete all firewall rules configured and reset the rulebase to the default rules.
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --fwrules
NSX Manager password:

INFO: Deleting Firewall configuration:
INFO: Status Code 403
```
###Deleting multiple object types
```
python nsx-reset-environment.py --nsxmgr 10.29.4.211 --ipsets --macsets --fwrules
NSX Manager password:

SUCCESS: Retrieved list of IP Sets in scope | globalroot-0
INFO: Skipping Read Only IP Set ipset-1

SUCCESS: Retrieved list of MAC Sets in scope | globalroot-0
INFO: Skipping Read Only MAC Set macset-1
INFO: Skipping Hidden MAC Set macset-1
INFO: Skipping Facade Hidden MAC Set macset-1

INFO: Deleting Firewall configuration:
INFO: Status Code 204
```
