#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56009);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/02/15 02:47:03 $");

  script_name(english:"Solstice Enterprise Agent SNMP (snmpdx) Detection");
  script_summary(english:"Checks for Solstice Enterprise Agent SNMP");

  script_set_attribute(attribute:"synopsis", value:
"An SNMP-based configuration utility was discovered on the remote
port.");
  script_set_attribute(attribute:"description", value:
"Solstice Enterprise Agent (SNMP), an agent-management utility from
Oracle, was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/docs/cd/E19455-01/806-2905/806-2905.pdf");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_require_udp_ports(16161);
  script_dependencies("snmp_settings.nasl");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");


# These are most of the OIDs available, found using the documentation and
# a snmpwalk. We aren't actually using them, but I'm leaving them here
# as a reminder. These can be found in /var/snmp/mib/snmpdx.mib, but not
# in such a clean way.
oids = make_array(
  "1.3.6.1.4.1.42.2.15.1.0",  "sunMasterAgentStatusFile",
  "1.3.6.1.4.1.42.2.15.2.0",  "sunMasterAgentResourceConfigFile",
  "1.3.6.1.4.1.42.2.15.3.0",  "sunMasterAgentConfigurationDir",
  "1.3.6.1.4.1.42.2.15.4.0",  "sunMasterAgentTrapPort",
  "1.3.6.1.4.1.42.2.15.5.0",  "sunCheckSubAgentName",
  "1.3.6.1.4.1.42.2.15.6.0",  "sunMasterAgentPollInterval",
  "1.3.6.1.4.1.42.2.15.7.0",  "sunMasterAgentMaxAgentTimeOut",
  "1.3.6.1.4.1.42.2.15.8.0",  "sunSubAgentTable", # Not accessible - list of SunSubAgentEntry
  "1.3.6.1.4.1.42.2.15.9.0",  "sunSubAgentTableIndex",
  "1.3.6.1.4.1.42.2.15.10.0", "sunSubTreeConfigurationTable", # Not accessible - list of SunSubTreeConfigurationEntry
  "1.3.6.1.4.1.42.2.15.11.0", "sunSubTreeConfigurationTableIndex",
  "1.3.6.1.4.1.42.2.15.12.0", "sunSubTreeDispatchTable", # Not accessible - list of SunSubTreeDispatchEntry
  "1.3.6.1.4.1.42.2.15.13.0", "sunSubTreeDispatchTableIndex",

  "1.3.6.1.4.1.42.2.15.8.1.1",  "sunSubAgentID",
  "1.3.6.1.4.1.42.2.15.8.1.2",  "sunSubAgentStatus",
  "1.3.6.1.4.1.42.2.15.8.1.3",  "sunSubAgentTimeout",
  "1.3.6.1.4.1.42.2.15.8.1.4",  "sunSubAgentPortNumber",
  "1.3.6.1.4.1.42.2.15.8.1.5",  "sunSubAgentRegistrationFile",
  "1.3.6.1.4.1.42.2.15.8.1.6",  "sunSubAgentAccessControlFile",
  "1.3.6.1.4.1.42.2.15.8.1.7",  "sunSubAgentExecutable",
  "1.3.6.1.4.1.42.2.15.8.1.8",  "sunSubAgentVersionNum",
  "1.3.6.1.4.1.42.2.15.8.1.9",  "sunSubAgentProcessID",
  "1.3.6.1.4.1.42.2.15.8.1.10", "sunSubAgentName",
  "1.3.6.1.4.1.42.2.15.8.1.11", "sunSubAgentSystemUpTime",
  "1.3.6.1.4.1.42.2.15.8.1.12", "sunSubAgentEntry"
);

port = 16161;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

# Get the global community string for snmp
community = get_kb_item("SNMP/community");
if(!community)
  community = "public";

s = open_sock_udp(port, community);
if (!s) audit(AUDIT_SOCK_FAIL, port, "UDP");

# Get the important OIDs
status_file   = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.1.0"); # sunMasterAgentStatusFile
config_file   = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.2.0"); # sunMasterAgentResourceConfigFile
config_dir    = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.3.0"); # sunMasterAgentConfigurationDir
trap_port     = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.4.0"); # sunMasterAgentTrapPort
poll_interval = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.6.0"); # sunMasterAgentPollInterval
agent_timeout = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.7.0"); # sunMasterAgentMaxAgentTimeOut
close(s);


# Check if the OID was present
if(!isnull(status_file))
{
  register_service(port:port, ipproto:"udp", proto:"solaris-sea-snmp");

  if(report_verbosity > 0)
  {
    extra = 'The Solstice Enterprise Agent has the following properties :' +
      '\n' +
      '\n  Status file             : ' + status_file +
      '\n  Resource config file    : ' + config_file +
      '\n  Configuration directory : ' + config_dir +
      '\n  SNMP Trap port          : ' + trap_port +
      '\n  Poll interval           : ' + poll_interval +
      '\n  Agent timeout           : ' + agent_timeout +
      '\n';

    security_note(port:port, proto:"udp", extra:extra);
  }
  else
  {
    security_note(port:port, proto:"udp");
  }
}
