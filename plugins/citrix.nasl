# This script was written by John Lampe ... j_lampe@bellsouth.net
#
# Script is based on 
# Citrix Published Application Scanner version 2.0
# By Ian Vitek, ian.vitek@ixsecurity.com
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(11138);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2017/05/10 19:18:33 $");

 script_bugtraq_id(5817);
 script_osvdb_id(50617);

 script_name(english:"Citrix Published Applications Remote Enumeration");
 script_summary(english:"Find Citrix published applications");

 script_set_attribute(attribute:"synopsis", value:
"The remote Citrix service is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible for a remote attacker to enumerate published
applications that are allowed on the affected Citrix server.");
 script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/files/29932/hackingcitrix.txt.html");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Sep/292");
 script_set_attribute(attribute:"solution", value:
"Consult the advisory referenced above for tips about securing the
service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value:"2002/10/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2017 John Lampe...j_lampe@bellsouth.net");
 script_family(english:"Misc.");

 exit(0);
}


#script code starts here

port = 1604;
trickmaster =               raw_string(0x20,0x00,0x01,0x30,0x02,0xFD,0xA8,0xE3);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

get_pa =          raw_string(0x2A,0x00,0x01,0x32,0x02,0xFD);
get_pa = get_pa + raw_string(0xa8,0xe3,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x21,0x00);
get_pa = get_pa + raw_string(0x02,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);

if(!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (soc) {
    send (socket:soc, data:trickmaster);
    incoming = recv(socket:soc, length:1024);
    close(soc);

    # See Citrix-pa-scan from http://www.securiteam.com/exploits/5CP0B1F80S.html
    if ('\x02\x00\x06\x44' >< incoming) {
	soc = open_sock_udp(port);
        send(socket:soc, data:get_pa);
	incoming = recv(socket:soc, length:1024);
	if(incoming) security_warning(port:port, proto:"udp");
    }
}

