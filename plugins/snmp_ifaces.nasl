#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10551);
 script_version ("$Revision: 1.31 $");
 script_cvs_date ("$Date: 2011/05/24 20:37:09 $");
 
 script_name(english:"SNMP Request Network Interfaces Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of network interfaces cards of the remote host can be obtained via
SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of the network interfaces installed
on the remote host by sending SNMP requests with the OID 1.3.6.1.2.1.2.1.0

An attacker may use this information to gain more knowledge about
the target host." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Enumerates processes via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item("SNMP/community");
if(!community) exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);


number = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.2.1.0");
oid = "1.3.6.1.2.1.2.1.0";

network = NULL;

cnt = 0;

for (i=1; i<=number; i++)
{
 index = snmp_request_next (socket:soc, community:community, oid:oid);
 if ( index == NULL ) break;
 descr = snmp_request (socket:soc, community:community, oid:string("1.3.6.1.2.1.2.2.1.2.",index[1]));
 phys = snmp_request (socket:soc, community:community, oid:string("1.3.6.1.2.1.2.2.1.6.",index[1]));

 oid = index[0];

 network += 
 string (
 "\n Interface ", i, " information :\n",
 " ifIndex       : ", index[1], "\n",
 " ifDescr       : ", descr, "\n",
 " ifPhysAddress : ", hexstr(phys), "\n",
 "\n"
 );

 if (strlen(phys) == 6 )
 {
   str = hexstr(phys[0]) + ':' + hexstr(phys[1]) + ':' + hexstr(phys[2]) + ':' + hexstr(phys[3]) + ':' + hexstr(phys[4]) + ':' + hexstr(phys[5]); 
  set_kb_item(name:"SNMP/ifPhysAddress/" + cnt, value:str);
  cnt++;
 }
}


if(strlen(network))
{
 security_note(port:port, extra:network, protocol:"udp");
}
