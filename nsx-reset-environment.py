# Author:   Dale Coghlan
# Email:    dcoghlan@vmware.com
# Date:     11 Jun 2015
# Version:  1.0.0

# ------------------------------------------------------------------------------------------------------------------
# Set some variables. No need to change anything else after this section

# Set the managed object reference
_scope = 'globalroot-0'

# Uncomment the following line to hardcode the password. This will remove the password prompt.
#_password = 'VMware1!'
#_password = 'default'
#
# ------------------------------------------------------------------------------------------------------------------

import requests
import argparse
import getpass
import logging
import xml.etree.ElementTree as ET

try:
    # Only needed to disable anoying warnings self signed certificate warnings from NSX Manager.
    import urllib3
    requests.packages.urllib3.disable_warnings()
except ImportError:
    # If you don't have urllib3 we can just hide the warnings
    logging.captureWarnings(True)

parser = argparse.ArgumentParser(description="Bulk delete NSX Objects.")
parser.add_argument("--nsxmgr", help="NSX Manager hostname, FQDN or IP address", metavar="nsxmgr", dest="_nsxmgr", type=str, required=True)
parser.add_argument("--user", help="OPTIONAL - NSX Manager username (default: %(default)s)", metavar="user", dest="_user", nargs="?", const='admin')
parser.set_defaults(_user="admin")

# Set arguments to delete different objects
parser.add_argument('--force', help=argparse.SUPPRESS, dest='_force', action='store_true')
parser.add_argument('--ipsets', help="Delete all IP Sets", dest='_delIPSets', action='store_true')
parser.add_argument('--services', help="Delete all services", dest='_delServices', action='store_true')
parser.add_argument('--secgroups', help="Delete all security groups", dest='_delSecGroups', action='store_true')
parser.add_argument('--servicegroups', help="Delete all service groups", dest='_delServiceGroups', action='store_true')
parser.add_argument('--macsets', help="Delete all MAC sets", dest='_delMacSets', action='store_true')
parser.add_argument('--secpolicies', help="Delete all security policies", dest='_delSecPolicies', action='store_true')
parser.add_argument('--sectags', help="Delete all security tags", dest='_delSecTags', action='store_true')
parser.add_argument('--fwrules', help="Delete all firewall rules and reset to default", dest='_delFWRules', action='store_true')

args = parser.parse_args()

try:
    _password
except NameError:
    _password = getpass.getpass(prompt="NSX Manager password:")

# Reads command line flags and saves them to variables
_user = args._user
_nsxmgr = args._nsxmgr

_force = args._force
_delIPSets = args._delIPSets
_delServices = args._delServices
_delSecGroups = args._delSecGroups
_delServiceGroups = args._delServiceGroups
_delMacSets = args._delMacSets
_delSecPolicies = args._delSecPolicies
_delSecTags = args._delSecTags
_delFWRules = args._delFWRules

# Set the application content-type header value
_nsx_api_headers = {'Content-Type': 'application/xml'}

def f_delete_ip_set_all():
    print('')
    _get_ip_set_url = 'https://%s/api/2.0/services/ipset/scope/%s' % (_nsxmgr, _scope)
    _get_ip_set_reponse = requests.get((_get_ip_set_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    _get_ip_set_data = _get_ip_set_reponse.content
    _get_ip_set_root = ET.fromstring(_get_ip_set_data)

    if int(_get_ip_set_reponse.status_code) != 200:
        print('ERROR: Cannot retrieve list of IP Sets in scope| ' + _scope)
        return
    else:
        print ('SUCCESS: Retrieved list of IP Sets in scope | ' + _scope)

        for ipset in _get_ip_set_root.findall('ipset'):

            for extendedAttributes in ipset.findall('extendedAttributes'):

                if extendedAttributes.find('extendedAttribute'):

                    for extendedAttribute in extendedAttributes.findall('extendedAttribute'):

                        if ((extendedAttribute.find('name').text) == 'isReadOnly') and ((extendedAttribute.find('value').text) == 'true'):
                                print('INFO: Skipping Read Only IP Set "%s" (%s)' % (ipset.find('name').text,ipset.find('objectId').text))

                        else:
                            print('INFO: Deleting IP Set: "%s" (%s)' % (ipset.find('name').text,ipset.find('objectId').text))
                            _del_ip_set_url = 'https://%s/api/2.0/services/ipset/%s?force=true' % (_nsxmgr, ipset.find('objectId').text)
                            _del_ip_set_reponse = requests.delete((_del_ip_set_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

                else:
                    print('INFO: Deleting IP Set: "%s" (%s)' % (ipset.find('name').text,ipset.find('objectId').text))
                    _del_ip_set_url = 'https://%s/api/2.0/services/ipset/%s?force=true' % (_nsxmgr, ipset.find('objectId').text)
                    _del_ip_set_reponse = requests.delete((_del_ip_set_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

def f_delete_mac_set_all():
    print('')
    _get_mac_set_url = 'https://%s/api/2.0/services/macset/scope/%s' % (_nsxmgr, _scope)
    _get_mac_set_reponse = requests.get((_get_mac_set_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    _get_mac_set_data = _get_mac_set_reponse.content
    _get_mac_set_root = ET.fromstring(_get_mac_set_data)

    if int(_get_mac_set_reponse.status_code) != 200:
        print('ERROR: Cannot retrieve list of MAC Sets in scope| ' + _scope)
        return
    else:
        print ('SUCCESS: Retrieved list of MAC Sets in scope | ' + _scope)

        for macset in _get_mac_set_root.findall('macset'):

            for extendedAttributes in macset.findall('extendedAttributes'):

                if extendedAttributes.find('extendedAttribute'):

                    for extendedAttribute in extendedAttributes.findall('extendedAttribute'):

                        if ((extendedAttribute.find('name').text) == 'isReadOnly') and ((extendedAttribute.find('value').text) == 'true'):
                            print('INFO: Skipping Read Only MAC Set "%s" (%s)' % (macset.find('name').text,macset.find('objectId').text))

                        elif ((extendedAttribute.find('name').text) == 'isHidden') and ((extendedAttribute.find('value').text) == 'true'):
                            print('INFO: Skipping Hidden MAC Set "%s" (%s)' % (macset.find('name').text,macset.find('objectId').text))

                        elif ((extendedAttribute.find('name').text) == 'facadeHidden') and ((extendedAttribute.find('value').text) == 'true'):
                            print('INFO: Skipping Facade Hidden MAC Set "%s" (%s)' % (macset.find('name').text,macset.find('objectId').text))

                        else:
                            print('INFO: Deleting MAC Set: "%s" (%s)' % (macset.find('name').text,macset.find('objectId').text))
                            _del_mac_set_url = 'https://%s/api/2.0/services/macset/%s?force=true' % (_nsxmgr, macset.find('objectId').text)
                            _del_mac_set_reponse = requests.delete((_del_mac_set_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

                else:
                    print('INFO: Deleting MAC Set: "%s" (%s)' % (macset.find('name').text,macset.find('objectId').text))
                    _del_mac_set_url = 'https://%s/api/2.0/services/macset/%s?force=true' % (_nsxmgr, macset.find('objectId').text)
                    _del_mac_set_reponse = requests.delete((_del_mac_set_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

def f_delete_service_all():
    defautServicesList = ['SAP JMS Adapter', 'SAP IPC data loader', 'SAP IBM', 'IPv6-ICMP Multicast Listener Done', 'Office Server Web Services, HTTP, SSL', 'SAP Cruiser', 'SAP Inst on IBM', 'SAP Lotus Domino - Proxy', 'SAP IIOPS', 'TELNET', 'Yahoo Messenger (UDP)', 'SAP Backup Server', 'SAP Mapping Manager', 'NetBios Datagram (TCP)', 'SAP Pre Processor 2', 'Oracle Internet Directory(non-SSL, 4032)', 'SAP Name Server', 'NetBios Session Service (TCP)', 'Win - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS - UDP', 'Win 2003 - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS', 'DHCP, MADCAP', 'IPv6-Opts', 'SAP Msg Svr HTTP', 'SAP Index Server 2', 'SAP GRMG Service (Heartbeat)', 'IPv6-ICMP Redirect', 'IGMP V2 Membership Report', 'SAP Upgrade', 'Yahoo Messenger (TCP)', 'ICMP Destination Unreachable', 'ICMP Redirect', 'SAP Exchange Groupware Connector (DCOM)', 'SAP SDM/SL', 'SAP Monitoring (GRMG)', 'ICMP Echo', 'ORACLE-FORM-SERVICES', 'IGMP V3 Membership Report', 'IPv6-NoExt', 'RTSP (UDP)', 'SAP Layout Server Quark Express', 'DHCPv6 Server', 'ICMP Time Exceeded', 'SAP PAW Servlet Engine', 'SAP P4 over SSL', 'SAP Content Server', 'SAP IPC Dispatcher Mobile client', 'SAP File Adapter', 'SAP Enqueue Repl 2', 'SAP RFC Server', 'SNMP', 'IPv6-ICMP Time Exceeded', 'SAP IPC Server', 'NFS (UDP)', 'SAP PAW Communication Server', 'SAP Telnet', 'RTSP (TCP)', 'SAP Start Service 2', 'SAP Central Software Deployment Manager', 'SAP JMS', 'SAP IIOP initial', 'SAP Import Mgr', 'SAP Msg Svr 2', 'IPv6-ICMP Neighbor Advertisement', 'SAP Alert Server', 'ISAKMP', 'SAP P4', 'Oracle Connection Manager (CMAN)', 'Syslog (UDP)', 'SAP Layout Server Adobe InDesign', 'H323 Gatekeeper RAS', 'NFS (TCP)', 'MSN (UDP)', 'Win - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS - TCP', 'IGMP Leave Group', 'Skinny', 'RPC, DFSR (SYSVOL)', 'SAP Oracle Listener', 'KERBEROS-TCP', 'SAP HostControl', 'SAP gateway/replication', 'SAP Inter Server COmm', 'Terminal Services (UDP)', 'ORACLE_TNS', 'PC Anywhere (UDP)', 'SAP Enqueue Svr', 'Syslog (TCP)', 'SAP Syndicator Service', 'IPv6-ICMP Neighbor Solicitation', 'SAP Layout Server', 'MSN (TCP)', 'SAP Gateway Netweaver App Server', 'SAP HTTP', 'SIP 5061', 'SIP 5060', 'SAP Router', 'IPv6-ICMP Parameter Problem', 'DHCPv6 Client', 'SAP Java Join', 'Terminal Services (TCP)', 'PC Anywhere (TCP)', 'SAP Dispatcher', 'IPv6-ICMP Router Advertisement', 'MS_RPC_UDP', 'SAP HTTP Server', 'SUN_RPC_UDP', 'IPv6-ICMP Echo Reply', 'SAP Start Service', 'ORACLE-XDB-FTP', 'SAP JMS/JDBC/File Adapter Server', 'NetBios Name Service (UDP)', 'SAP HTTP Server 2', 'sys-gen-empty-app-edge-fw', 'SAP HostControlS', 'H323 Call Signaling', 'IPv6-ICMP Packet Too Big', 'IGMP Membership Query', 'SAP Queue Server', 'Oracle Connection Manager Admin (CMAN)', 'OC4J Forms / Reports Instance (8889)', 'IPv6-ICMP Router Solicitation', 'SAP HTTPS', 'SAP IIOP', 'SAP Queue Server 2', 'Win 2008 - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS', 'MS-DS', 'NetBios Name Service (TCP)', 'ICMP Router Advertisement', 'VMware Consolidated Backup', 'IPv6-ICMP Multicast Listener Report', 'SAP gateway - CPIC/RFC', 'HTTPS, net.tcp binding', 'SAP Design Time Repository', 'Microsoft Media Server (UDP)', 'MGCP (UDP)', 'SAP LiveCache', 'T120 (Whiteboard A43)', 'SAP JDBCAdapter', 'SAP Pre Processor', 'IPv6-ICMP Multicast Listener Query', 'IKE (Key Exchange)', 'SAP Java Debug', 'SAP Index Server', 'SAP Inst', 'SAP Name Server 2', 'NTP', 'IPv6-ICMP Destination Unreachable', 'SAP Layout Server 2', 'ICMP Router Solicitation', 'Microsoft Media Server (TCP)', 'MGCP (TCP)', 'FTP', 'IKE (Traversal)', 'SMB', 'SAP Comm', 'SAP Msg Svr', 'OC4J Forms / Reports Instance', 'SUN_RPC_TCP', 'IPv6-ICMP Echo', 'SAP Dispatcher Netweaver App Server', 'SAP ICM HTTP', 'Oracle Internet Directory(SSL, 4031)', 'ICMP Echo Reply', 'SAP MDM Server', 'SAP Admin console', 'SAP SNC secured gateway', 'SAP printer spooler', 'SAP IPC Dispatcher Mobile client 2', 'SAP P4 over HTTP', 'SAP Message Server HTTP', 'SAP Lotus Domino - Connector', 'H323 Gatekeeper Discovery', 'SAP network Test Program', 'SAP Cache Server', 'NetBios Datagram (UDP)', 'ORACLE-HTTP', 'NetBios Session Service (UDP)', 'ICMP Source Quench', 'VMware-DataRecovery', 'VMware-VC-Syslog', 'Vmware-VCHeartbeat', 'Vmware-Heartbeat-PrimarySecondary', 'EdgeSync service/ADAM', 'MS Unified Messaging server', 'MS Replication service', 'MS Customizable', 'Office communication server', 'SMTP_TLS', 'EdgeSync service', 'MS Unified Messaging server - Client Access', 'LDAP Global Catalog', 'MS Unified Messaging server-Phone', 'SQL Server Browser service', 'SQL Analysis service', 'MS-SQL-M-TCP', 'SOAP', 'WINS', 'Windows-Global-Catalog', 'Windows-Global-Catalog-over-SSL', 'NTP Time Server', 'Active Directory Server', 'WINS-UDP', 'IMAP_SSL', 'For X.400 connections over TCP', 'IMAP', 'POP3', 'Routing Engine service', 'Site Replication service', 'NNTP_SSL', 'Exchange ActiveSync', 'POP3_SSL', 'NNTP', 'Oracle Notification Service request port', 'OracleAS Certificate Authority (OCA) - Server Authentication', 'Oracle Notification Service local port', 'Oracle HTTP Server listen port', 'Oracle Intelligent Agent (1754)', 'OS Agent', 'Enterprise Manager Reporting port', 'DCM Java Object Cache port', 'Oracle HTTP Server port', 'Oracle9iAS Web Cache HTTP Listen(SSL) port', 'Oracle OC4J AJP', 'Oracle OC4J IIOPS2', 'Oracle Internet Directory(SSL)', 'Oracle OC4J IIOPS1', 'Oracle HTTP Server SSL port', 'Oracle9iAS Web Cache HTTP Listen(non-SSL) port', 'Oracle Internet Directory(non-SSL)', 'Oracle SOAP Server', 'Oracle9iAS Web Cache Invalidation port', 'Java Object Cache port', 'Oracle Intelligent Agent (1808)', 'Oracle9iAS Web Cache Statistics port', 'Oracle9iAS Web Cache Admin port', 'Oracle HTTP Server Jserv port', 'Oracle Forms Server 6 / 6i', 'Oracle OC4J JMS', 'Oracle OC4J RMI', 'Oracle9iAS Clickstream Collector Agent', 'Oracle Intelligent Agent (1809)', 'Oracle HTTP Server Diagnostic Port', 'Oracle HTTP Server Port Tunneling', 'Oracle OC4J IIOP', 'Oracle Notification Service remote port', 'Oracle Intelligent Agent (1748)', 'OracleAS Certificate Authority (OCA) - Mutual Authentication', 'Oracle GIOP IIOP', 'Oracle GIOP IIOP for SSL', 'Oracle Names', 'Oracle XMLDB FTP Port', 'Oracle Net Listener', 'Oracle XMLDB HTTP port', 'Oracle Net Listener / Enterprise Manager Repository port', 'Enterprise ManagerAgent port', 'Log Loader', 'Enterprise Manager Servlet port SSL', 'Enterprise Manager RMI port', 'Oracle Enterprise Manager Web Console', 'Oracle JDBC for Rdb Thin Server', 'Oracle TimesTen (4761)', 'Oracle TimesTen (4764)', 'Oracle TimesTen (4758)', 'Oracle TimesTen (4766)', 'Oracle Times Ten (15004)', 'Oracle TimesTen', 'Oracle Times Ten (15000)', 'Oracle TimesTen (4759)', 'Oracle TimesTen (4767)', 'Oracle Times Ten (15002)', 'iSQLPlus 10g (5580)', 'iSQLPlus 10g', 'VMware-VCO-VCO-HTTPS', 'VMware-VCO-WebHTTPS', 'VMware-VCO-WebHTTP', 'VMware-VCO-Command', 'PostgresSQL', 'MySQL', 'VMware-VCO-Data', 'VMware-VCO-Messaging', 'Vmware-VCO-Lookup', 'NBDG-Unicast', 'NBDG-Broadcast', 'NBNS-Unicast', 'SMB Server UDP', 'NBSS', 'SMB Server', 'LDAP-over-SSL-UDP', 'Server Message Block (SMB)', 'NBNS-Broadcast', 'Active Directory Server UDP', 'Directory Services', 'VMware-SRM-Replication', 'VMware-SRM-vCentreServer', 'Vmware-VCO-VCO-HTTP', 'VMware-SRM-vSphereReplication', 'VMware-SRM-SOAP', 'VMware-SRM-HTTP', 'VMware-SRMClient-Server', 'IBM DB2', 'Oracle-2', 'Vmware-SRM-WSDL-vCentreServer', 'VMware-SRM-UI', 'VMware-UpdateMgr', 'VMware-UpdateMgr-Patching', 'VMware-UpdateMgr-SOAP', 'Vmware-UpdateMgr-update', 'VMware-UpdateMgr-VUM', 'AD Server', 'VMware-SPS', 'Vmware-FT-TCP', 'VMware-iSCSI-Server', 'DHCP-Client', 'NFS-Server-TCP', 'Syslog-Server', 'DNS-UDP', 'DHCP-Server', 'NFS-Server-UDP', 'RFB', 'NFS Client', 'VMware-HA-UDP', 'NFS Client UDP', 'VMware-HA-TCP', 'VMware VMotion', 'VMware-CIMSLP', 'VMware-DVS', 'Vmware-FT-UDP', 'Syslog-Server-UDP', 'VMware-VC-DumpSvr', 'VMware-View5.x-PCoIP-UDP', 'VMware-View-PCoIP', 'RDP', 'VMware-VDM2.x-Ephemeral', 'VMware-View5.x-JMS', 'Vmware-VDM2.x-AJP', 'MS-DS-UDP', 'MS-DS-TCP', 'VMware-VDM2.x-RGS', 'Vmware-VDM2.x-JMS', 'VMware-VC-RemoteConsole', 'VMware-VC-DumpCollector-TCP', 'VMware-VC-DPM', 'KERBEROS-UDP', 'SNMP-Recieve', 'Vmware-VC-WebAccess', 'VMware-SRM-VAMI', 'VMware-VC-ESXi', 'VMware-ESXi5.x-UDP', 'CIM-HTTPS', 'Vmware-VC-VC-Internal', 'SMTP', 'MS_RPC_TCP', 'LDAP-UDP', 'LDAP-over-SSL', 'DNS', 'SNMP-Send', 'Oracle', 'MS-SQL-M', 'MS-SQL-S', 'Vmware-VC-HTTP', 'CIM-HTTP', 'KERBEROS', 'LDAP', 'VMware-ESXi5.x-TCP', 'Vmware-VCOStdAln-Remote', 'VMware-VCOStdAln-Heartbeat', 'HTTP', 'VMware-VCOMgr-UI', 'SSH', 'HTTPS', 'HBR Server App']
    defaultFWRuleServicesList = ['IPv6-ICMP Neighbor Advertisement', 'IPv6-ICMP Neighbor Solicitation', 'DHCP-Client', 'DHCP-Server']
    print('')

    _get_ip_service_url = 'https://%s/api/2.0/services/application/scope/%s' % (_nsxmgr, _scope)
    _get_ip_service_reponse = requests.get((_get_ip_service_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    _get_ip_service_data = _get_ip_service_reponse.content
    _get_ip_service_root = ET.fromstring(_get_ip_service_data)

    if int(_get_ip_service_reponse.status_code) != 200:
        print('ERROR: Cannot retrieve list of Services in scope| ' + _scope)
        return

    else:
        print ('SUCCESS: Retrieved list of Services in scope | ' + _scope)

        for service in _get_ip_service_root.findall('application'):

            if _force == True:

                for extendedAttributes in service.findall('extendedAttributes'):

                    if extendedAttributes.find('extendedAttribute'):

                        for extendedAttribute in extendedAttributes.findall('extendedAttribute'):

                            if ((extendedAttribute.find('name').text) == 'isReadOnly') and ((extendedAttribute.find('value').text) == 'true'):
                                print('INFO: Skipping Read Only Service "%s" (%s)' % (service.find('name').text,service.find('objectId').text))

                            else:
                                if service.find('name').text not in defaultFWRuleServicesList:
                                    print('INFO: Deleting Service: "%s" (%s)' % (service.find('name').text,service.find('objectId').text))
                                    _del_ip_service_url = 'https://%s/api/2.0/services/application/%s?force=true' % (_nsxmgr, service.find('objectId').text)
                                    _del_ip_service_reponse = requests.delete((_del_ip_service_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

                    else:
                        if service.find('name').text not in defaultFWRuleServicesList:
                            print('INFO: Deleting Service: "%s" (%s)' % (service.find('name').text,service.find('objectId').text))
                            _del_ip_service_url = 'https://%s/api/2.0/services/application/%s?force=true' % (_nsxmgr, service.find('objectId').text)
                            _del_ip_service_reponse = requests.delete((_del_ip_service_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)


            else:

                if service.find('name').text not in defautServicesList:

                    for extendedAttributes in service.findall('extendedAttributes'):

                        if extendedAttributes.find('extendedAttribute'):

                            for extendedAttribute in extendedAttributes.findall('extendedAttribute'):

                                if ((extendedAttribute.find('name').text) == 'isReadOnly') and ((extendedAttribute.find('value').text) == 'true'):
                                    print('INFO: Skipping Read Only Service "%s" (%s)' % (service.find('name').text,service.find('objectId').text))

                                else:
                                    print('INFO: Deleting Service: "%s" (%s)' % (service.find('name').text,service.find('objectId').text))
                                    _del_ip_service_url = 'https://%s/api/2.0/services/application/%s?force=true' % (_nsxmgr, service.find('objectId').text)
                                    _del_ip_service_reponse = requests.delete((_del_ip_service_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

                        else:
                            print('INFO: Deleting Service: "%s" (%s)' % (service.find('name').text,service.find('objectId').text))
                            _del_ip_service_url = 'https://%s/api/2.0/services/application/%s?force=true' % (_nsxmgr, service.find('objectId').text)
                            _del_ip_service_reponse = requests.delete((_del_ip_service_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

def f_delete_sec_group_all():
    print('')
    _get_sec_group_url = 'https://%s/api/2.0/services/securitygroup/scope/%s' % (_nsxmgr, _scope)
    _get_sec_group_reponse = requests.get((_get_sec_group_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    _get_sec_group_data = _get_sec_group_reponse.content
    _get_sec_group_root = ET.fromstring(_get_sec_group_data)

    if int(_get_sec_group_reponse.status_code) != 200:
        print('ERROR: Cannot retrieve list of Security Groups in scope| ' + _scope)
        return

    else:
        print ('SUCCESS: Retrieved list of Security Groups in scope | ' + _scope)

        for sgid in _get_sec_group_root.findall('securitygroup'):

            if ((sgid.find('name').text) == 'Activity Monitoring Data Collection'):
                print('INFO: Skipping Security Group "%s" (%s)' % (sgid.find('name').text,sgid.find('objectId').text))

            else:
                print('INFO: Deleting Security Group: "%s" (%s)' % (sgid.find('name').text,sgid.find('objectId').text))
                _del_sec_group_url = 'https://%s/api/2.0/services/securitygroup/%s?force=true' % (_nsxmgr, sgid.find('objectId').text)
                _del_sec_group_reponse = requests.delete((_del_sec_group_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

def f_delete_service_group_all():
    defaultServiceGroupList = ['Data Recovery Appliance', 'Heartbeat', 'Microsoft Active Directory', 'Microsoft Exchange 2003', 'MS Exchange 2007 Transport Servers', 'MS Exchange 2007 Unified Messaging Centre', 'MS Exchange 2007 Client Access Server', 'MS Exchange 2007 Mailbox Servers', 'Microsoft Exchange 2007', 'MS Exchange 2010 Client Access Servers', 'MS Exchange 2010 Transport Servers', 'MS Exchange 2010 Mailbox Servers', 'MS Exchange 2010 Unified Messaging Server', 'Microsoft Exchange 2010', 'MSSQL Server Database Engine', 'MSSQL Reporting Services', 'MSSQL Server Analysis Services', 'MSSQL Integration Services', 'Microsoft SQL Server', 'Oracle Application Server', 'Oracle Database', 'Oracle Enterprise Manager', 'Oracle Enterprise Manager Web', 'Oracle Rdb', 'Oracle Times Ten', 'Oracle i*SQLPlus', 'Orchestrator', 'SharePoint 2007', 'SharePoint 2010', 'Site Recovery Manager 5.x', 'Update Manager', 'ESXi Syslog Collector', 'VMware ESXi 5.x', 'VMware ESXi Dump Collector', 'View 5.x', 'Vmware View/VDM2.x', 'vCenter5.x', 'vCentre Operations Manager (Standalone) 5.x', 'vCentre Operations Manager (vApp) 5.x', 'vCentre Operations Standard', 'vCentre Operations Standard 1.x']
    print('')

    _get_service_group_url = 'https://%s/api/2.0/services/applicationgroup/scope/%s' % (_nsxmgr, _scope)
    _get_service_group_reponse = requests.get((_get_service_group_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    _get_service_group_data = _get_service_group_reponse.content
    _get_service_group_root = ET.fromstring(_get_service_group_data)

    if int(_get_service_group_reponse.status_code) != 200:
        print('ERROR: Cannot retrieve list of Service Groups in scope| ' + _scope)
        return

    else:
        print ('SUCCESS: Retrieved list of Service Groups in scope | ' + _scope)

        for srvgroupid in _get_service_group_root.findall('applicationGroup'):

            if _force == True:
                print('INFO: Deleting Service Group: "%s" (%s)' % (srvgroupid.find('name').text,srvgroupid.find('objectId').text))
                _del_service_group_url = 'https://%s/api/2.0/services/applicationgroup/%s?force=true' % (_nsxmgr, srvgroupid.find('objectId').text)
                _del_sec_group_reponse = requests.delete((_del_service_group_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

            else:
                if srvgroupid.find('name').text not in defaultServiceGroupList:
                    print('INFO: Deleting Service Group: "%s" (%s)' % (srvgroupid.find('name').text,srvgroupid.find('objectId').text))
                    _del_service_group_url = 'https://%s/api/2.0/services/applicationgroup/%s?force=true' % (_nsxmgr, srvgroupid.find('objectId').text)
                    _del_sec_group_reponse = requests.delete((_del_service_group_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)


def f_delete_security_policy_all():
    print('')
    _get_security_policy_url = 'https://%s/api/2.0/services/policy/securitypolicy/all' % (_nsxmgr)
    _get_security_policy_reponse = requests.get((_get_security_policy_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    _get_security_policy_data = _get_security_policy_reponse.content
    _get_security_policy_root = ET.fromstring(_get_security_policy_data)

    if int(_get_security_policy_reponse.status_code) != 200:
        print('ERROR: Cannot retrieve list of Security Policies')
        return

    else:
        print ('SUCCESS: Retrieved list of Security Policies')

        for securitypolicy in _get_security_policy_root.findall('securityPolicy'):

            for extendedAttributes in securitypolicy.findall('extendedAttributes'):

                if extendedAttributes.find('extendedAttribute'):

                    for extendedAttribute in extendedAttributes.findall('extendedAttribute'):

                        if ((extendedAttribute.find('name').text) == 'isHidden') and ((extendedAttribute.find('value').text) == 'true'):
                                print('INFO: Skipping hidden security policy "%s" (%s)' % (securitypolicy.find('name').text,securitypolicy.find('objectId').text))

                        else:
                            print('INFO: Deleting Security Policy: "%s" (%s)' % (securitypolicy.find('name').text,securitypolicy.find('objectId').text))
                            _del_security_policy_url = 'https://%s/api/2.0/services/policy/securitypolicy/%s?force=true' % (_nsxmgr, securitypolicy.find('objectId').text)
                            _del_security_policy_reponse = requests.delete((_del_security_policy_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

                else:
                    print('INFO: Deleting Security Policy: "%s" (%s)' % (securitypolicy.find('name').text,securitypolicy.find('objectId').text))
                    _del_security_policy_url = 'https://%s/api/2.0/services/policy/securitypolicy/%s?force=true' % (_nsxmgr, securitypolicy.find('objectId').text)
                    _del_security_policy_reponse = requests.delete((_del_security_policy_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)

def f_delete_security_tag_all():
    print('')
    _get_security_tag_url = 'https://%s/api/2.0/services/securitytags/tag' % (_nsxmgr)
    _get_security_tag_reponse = requests.get((_get_security_tag_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    _get_security_tag_data = _get_security_tag_reponse.content
    _get_security_tag_root = ET.fromstring(_get_security_tag_data)

    if int(_get_security_tag_reponse.status_code) != 200:
        print('ERROR: Cannot retrieve list of Security Tags')
        return

    else:
        print ('SUCCESS: Retrieved list of Security Tags')

        for securitytag in _get_security_tag_root.findall('securityTag'):

            if (securitytag.find('systemResource').text == 'true'):
                print('INFO: Skipping system security tag "%s" (%s)' % (securitytag.find('name').text,securitytag.find('objectId').text))

            else:
                print('INFO: Deleting Security tag: "%s" (%s)' % (securitytag.find('name').text,securitytag.find('objectId').text))
                _del_security_tag_url = 'https://%s/api/2.0/services/securitytags/tag/%s' % (_nsxmgr, securitytag.find('objectId').text)
                _del_security_tag_reponse = requests.delete((_del_security_tag_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)


def f_delete_firewall_config_all():
    print('')
    print('INFO: Deleting Firewall configuration:')
    _delete_firewall_config_url = 'https://%s/api/4.0/firewall/globalroot-0/config' % (_nsxmgr)
    _delete_firewall_config_reponse = requests.delete((_delete_firewall_config_url), headers=_nsx_api_headers, auth=(_user, _password), verify=False)
    print('INFO: Status Code %i' % _delete_firewall_config_reponse.status_code)

if _delFWRules == True:
    f_delete_firewall_config_all()
if _delIPSets == True:
    f_delete_ip_set_all()
if _delServices == True:
    f_delete_service_all()
if _delSecGroups == True:
    f_delete_sec_group_all()
if _delServiceGroups == True:
    f_delete_service_group_all()
if _delMacSets == True:
    f_delete_mac_set_all()
if _delSecPolicies == True:
    f_delete_security_policy_all()
if _delSecTags == True:
    f_delete_security_tag_all()

exit()
