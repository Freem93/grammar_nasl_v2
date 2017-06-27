#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10688);
 script_version ("$Revision: 1.29 $");

 script_cve_id("CVE-2004-1775");
 script_bugtraq_id(5030);
 script_osvdb_id(58150);

 script_name(english:"Cisco CatOS VACM read-write Community String Device Configuration Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The SNMP private community strings can be retrieved using SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the remote private community strings using
the View-Based Access Control MIB (VACM) of the remote Cisco router. 
An attacker may use this flaw to gain read/write SNMP access on this
router.

Note that a value in this table does not necessarily mean that an
instance with the value exists in table vacmAccessTable.  The SNMP
private community string(s) returned may only allow read access." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197acbde" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df9dee8f" );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port or install Cisco patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/15");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Enumerates communities via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl","snmp_sysDesc.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

oid = get_kb_item_or_exit("SNMP/OID");

# Only checks for cisco, else it could be FP
if (!is_valid_snmp_product(manufacturer:"1.3.6.1.4.1.9.1", oid:oid))
  exit (0, "The host does not appear to be a Cisco device.");

community = get_kb_item_or_exit("SNMP/community");

port = get_kb_item("SNMP/port");
if(!port)port = 161;

if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
soc = open_sock_udp(port);
if (!soc)
  exit (0, "Failed to open a socket on UDP port "+port+".");

comms = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.6.3.16.1.2.1.3");

if(strlen(comms))
{
 security_hole(port:port, extra: comms, protocol:"udp");
 exit(0);
}
else exit(0, "The host is not affected.");
