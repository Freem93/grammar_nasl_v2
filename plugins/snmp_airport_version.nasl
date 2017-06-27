#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(45022);
 script_version ("$Revision: 1.3 $");
 script_cvs_date("$Date: 2017/02/16 21:23:30 $");
 
 script_name(english:"SNMP Query Airport Version");
 
 script_set_attribute(attribute:"synopsis", value:
"The version of the remote Airport device can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the version and model type of the remote
Airport device by sending SNMP requests to the remote host. 

An attacker may use this information to gain more knowledge about the
target network." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/10" );
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Enumerates system info via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

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
if(!port) port = 161;
if (!get_udp_port_state(port)) exit(1, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit(1, "Failed to open a socket on UDP port "+port+"."); 


model = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.63.501.3.1.1.0");
if ( isnull(model) ) exit(0, "Not an Airport Device.");
firmware = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.63.501.3.1.5.0");
 
report = "";
if ( model && firmware )
{
 set_kb_item(name:"Host/Airport/Firmware", value:firmware);
 report += 'Device name : '  + model + '\n';
 report += 'Firmware version : ' + firmware + '\n';
 is_dhcp = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.63.501.3.3.1.0");
 if ( is_dhcp == 0 ) report += 'DHCP Server : NO\n';
 else {
  report += 'DHCP Server : YES\n';
  oid = soid = "1.3.6.1.4.1.63.501.3.3.2.1.2";
  seen = make_array();
  num = 0;
  while ( TRUE )
  {
   num ++;
   if ( num > 50 ) break;
   v = snmp_request_next(socket:soc, community:community, oid:soid);
   if ( isnull(v) ) break;
   if ( !issameoid(origoid:oid, oid:v[0]) ) break;
   if ( !isnull(seen[v[1]]) ) break;
   toid = str_replace(string:v[0], find:"1.3.6.1.4.1.63.501.3.3.2.1.2", replace:"1.3.6.1.4.1.63.501.3.3.2.1.1");
   mac = snmp_request(socket:soc, community:community, oid:toid);
   seen[v[1]] = mac;
   soid = v[0];
  }

  if ( max_index(keys(seen)) > 0 )
  {
  report += 'List of IP addresses handed out by the DHCP server :\n';
  foreach item ( sort(keys(seen)) )
   report += 'IP address : ' + item + ', MAC address : ' + seen[item] + '\n';
  }
 }
 security_note(port:port, extra:report, proto:"udp");
}

