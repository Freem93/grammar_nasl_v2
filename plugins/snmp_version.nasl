#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35296);
 script_version ("$Revision: 1.9 $");

 script_name(english:"SNMP Protocol Version Detection");
 script_summary(english:"Reports negotiated SNMP version from KB");

 script_set_attribute(attribute:'synopsis',value:
"This plugin reports the protocol version negotiated with the remote
SNMP agent." );
 script_set_attribute(attribute:'description',value:
"By sending an SNMP 'get-next-request', it is possible to determine the
protocol version of the remote SNMP agent." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://en.wikipedia.org/wiki/Simple_Network_Management_Protocol"
 );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/06");
 script_cvs_date("$Date: 2011/05/24 20:37:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english:"SNMP");

 script_dependencies("snmp_settings.nasl");
 script_require_keys("SNMP/community", "SNMP/version");
 exit(0);
}

include ("snmp_func.inc");

port = get_kb_item("SNMP/port");

if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
soc = open_sock_udp(port);
if (!soc)
  exit (0);


community = get_kb_item("SNMP/community");
if(!community)exit(0);

version = get_kb_item("SNMP/version");
if (isnull(version) || version == 0) version = "SNMPv1"; # For SNMPv1 version is either set to 0 or NULL.
else if (version == 1)	version = "SNMPv2c";
else if (version == 3)	version = "SNMPv3";

if (version)
{
  report = string('\n', "Nessus has negotiated SNMP communications at ", version, ".", '\n');
  security_note(port:port, extra:report, proto:"udp");
}
