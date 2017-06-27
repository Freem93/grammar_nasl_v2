#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(43100);
 script_version ("$Revision: 1.2 $");
 script_cvs_date("$Date: 2011/03/11 21:52:39 $");
 
 script_name(english:"SNMP Query WLAN SSID (Cisco)");
 
 script_set_attribute(attribute:"synopsis", value:
"The SSID of the remote wireless LAN can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the system information about the remote WLAN
by sending SNMP requests with the OID 1.3.6.1.4.1.9.9.512.1.1.1.1.4.1
to the remote Access Point controller. 

An attacker may use this information to gain more knowledge about the
target network." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/10" );
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Enumerates system info via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

 script_family(english:"SNMP");
 script_dependencie("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}


include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(1, "The 'SNMP/community' KB item is missing.");

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (!get_udp_port_state(port)) exit(1, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (1, "Can't open socket to UDP port "+port+".");


ssid = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.512.1.1.1.1.4.1");
if (! isnull(ssid) )
{
 set_kb_item(name:"SNMP/WLAN/SSID", value:ssid);
 security_note(port:port, proto:"udp", extra:'
The remote host is a wireless access point controller, serving the following
SSID :\n\n' + ssid);
}
