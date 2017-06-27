#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34022);
 script_version ("$Revision: 1.11 $");
 script_cvs_date("$Date: 2011/05/24 20:37:09 $");

 script_name(english: "SNMP Query Routing Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of IP routes on the remote host can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the routing information on the remote host
by sending SNMP requests with the OID 1.3.6.1.2.1.4.21

An attacker may use this information to gain more knowledge about the
network topology." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "Enumerates routes via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_family(english: "SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#

include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

ipRouteInfo = make_list();
ri = 0;

# ipRouteInfo
roid = "1.3.6.1.2.1.4.21.1.1"; 
oid = roid;
while (1)
{
  v = snmp_request_next(socket: soc, community: community, oid: oid);
  if (isnull(v) || ! issameoid(origoid: roid, oid: v[0])) break;
  oid = v[0];
  ipRouteInfo[ri++] = v[1];
}

if (ri == 0 || ri == 1 && ipRouteInfo[0] == "0.0.0.0") exit(0);

ipRouteMask = make_list();
mi = 0;
# ipRouteMask
roid = "1.3.6.1.2.1.4.21.1.11";
oid = roid;
while (1)
{
  v = snmp_request_next(socket: soc, community: community, oid: oid);
  if (isnull(v) || ! issameoid(origoid: roid, oid: v[0])) break;
  oid = v[0];
  ipRouteMask[mi++] = v[1];
}

report = '\n';
for (i = 0; i < mi || i < ri; i ++)
  if (ipRouteInfo[i] != '0.0.0.0' || ipRouteMask[i] != '0.0.0.0')
    report = strcat(report, ipRouteInfo[i], '/', ipRouteMask[i], '\n');

security_note(port: port, proto: 'udp', extra: report);

