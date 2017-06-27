#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20345);
 script_version ("$Revision: 1.18 $");
 
 script_name(english:"Airport Administrative Traffic Detection (192/UDP)");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a wireless access point." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Airport, Airport Extreme or Airport Express
wireless access point.  It is possible to gather information about the
remote base station (such as its connection type or connection time)
by sending packets to UDP port 192. 

An attacker connected to this network may also use this protocol to
force the base station to disconnect from the network if it is using
PPPoE, thus causing a denial of service for the other users." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port and make sure only authorized
hosts can connect to the wireless network this base station listens
on." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/27");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Sends a message to UDP port 192");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 exit(0);
}

#

include("byte_func.inc");

Airport_Status_Request = raw_string(0x08, 0x01, 0x03, 0x10);
Airport_Connection_Time_Offset = 34;
Airport_Connection_Type_Offset = 6;

Airport_Connection_Type_DHCP_or_STATIC   = 0x01;
Airport_Connection_Type_PPTP   = 0x04;
Airport_Connection_Type_Client = 0x00;

port = 192;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (! soc ) exit(0);
send(socket:soc, data:Airport_Status_Request);
r = recv(socket:soc, length:4096);
if ( ! r || strlen(r) < 38 ) exit(0);

connType = getbyte(blob:r, pos:Airport_Connection_Type_Offset);

l = getdword(blob:r, pos:Airport_Connection_Time_Offset);
days = l / (3600*24);
l    -= ( days * 3600 * 24 );
hours = l / 3600;
l    -= ( hours * 3600 );
mins  = l / 60;
l    -= ( mins * 60 );
secs  = l;



if ( l != 0 ) report = " - The station has been connected to the network for " + days + " days " + hours + "h" + mins + "m" + secs + "s";
if ( connType == Airport_Connection_Type_PPTP )
   report += '\n - The station is connected to the network via PPTP\n';
else if ( connType == Airport_Connection_Type_DHCP_or_STATIC )
   report += '\n - The station is connected to the network via DHCP or a static IP address\n';
else if ( connType == 0 && l == 0 )
   report += '\n - The station is a client on the network (acting as a bridge)\n';

security_warning(port:port, extra:report, proto:"udp");
