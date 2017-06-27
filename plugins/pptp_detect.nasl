#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10622);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
 script_name(english:"PPTP Detection"); 

 script_set_attribute(attribute:"synopsis", value:
"A VPN server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a PPTP (Point-to-Point Tunneling Protocol)
server.  It allows users to set up a tunnel between their host and the
network the remote host is attached to." );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this software is in agreement with your
organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Connects to port 1723 to determine if a PPTP server is listening");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_require_ports(1723);
 exit(0);
}

port=1723;
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

if ( ! get_port_state(port) ) exit(0);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

pptp_head =	mkword(1) +			# Message Type
        	mkdword(0x1a2b3c4d) +		# Cookie
 		mkword(1) +			# Control type (Start-Control-Connection-Request)
		mkword(0) +			# Reserved
		mkword(0x0100) +		# Protocol Version (1.0)
  		mkword(0) +			# Reserved
		mkdword(1) +			# Framing Capabilities
		mkdword(1) +			# Bearer capabilities
		mkword(0);			# Maximum channels
pptp_vendor = mkword(NASL_LEVEL) +		# Firmware revision 
	      mkpad(64) +			# Hostname 
	      mkpad(64);			# Vendor


pptp = mkword(strlen(pptp_head) + strlen(pptp_vendor) + 2) + pptp_head + pptp_vendor;

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:pptp);
r = recv(socket:soc, length:2);
if ( ! r || strlen(r) != 2 ) exit(0);
l = getword(blob:r, pos:0); 
r += recv(socket:soc, length:l - 2, min:l - 2);
if ( strlen(r) != l ) exit(0);
if ( strlen(r) < strlen(pptp_head) + strlen(pptp_vendor) ) exit(0);

cookie = getdword(blob:r, pos:4);
if ( cookie != 0x1a2b3c4d ) exit(0);

ptr = strlen(pptp_head) + 2;
firmware = getword(blob:r, pos:ptr);
ptr += 2;
rhostname = substr(r , ptr, ptr + 63);
for ( i = 0 ; ord(rhostname[i]) != 0 && i < 64;  i ++ )
 {
  hostname += rhostname[i];
 }

ptr += 64;
rvendor   = substr(r, ptr, ptr + 63);
for ( i = 0 ; ord(rvendor[i]) != 0 && i < 64;  i ++ )
 {
  vendor += rvendor[i];
 }

report = '';

if ( firmware != 0 || strlen(vendor) || strlen(hostname))
{
 report += 'It was possible to extract the following information from the remote PPTP server :\n\n';
 if ( firmware != 0 )
 	report += 'Firmware Version : ' + firmware + '\n';
 if ( strlen(vendor) != 0 )
 	report += 'Vendor Name : ' + vendor + '\n';
 if ( strlen(hostname) != 0 )
 	report += 'Host name : ' + hostname + '\n';
}


register_service(port:port, proto:"pptp");
if (report) security_note(port:port, extra:'\n'+report);
else security_note(port);
