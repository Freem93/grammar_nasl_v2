#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11387);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2017/05/16 19:43:12 $");

 script_name(english:"L2TP Network Server Detection");
 script_summary(english:"Determine if a remote host is running a L2TP (VPN) service");

 script_set_attribute(attribute:"synopsis", value:"A VPN service is listening on this port.");
 script_set_attribute(attribute:"description", value:
"The report host understands the L2TP tunneling protocol and appears to
be a VPN endpoint, or more specifically, an L2TP Network Server." );
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/L2TP");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

 exit(0);
}

port = 1701;
if ( ! get_kb_item("Settings/PCI_DSS")  )
{
 if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
}
		 
req = raw_string(0xC8, 2, 0, 76, 0, 0, 0, 0,0,0,0,0,
		 0x80, 8, 0,0,0,0,0,1,
		 0x80, 8, 0,0,0,2,1,0,
		 0x80, 10,0,0,0,3,0,0,0,3,
		 0x80, 10,0,0,0,4,0,0,0,0,
		 0x80, 12,0,0,0,7) + "nessus" +
      raw_string(0x80, 8, 0,0,0,8,42,42,
                 0x80, 8, 0,0,0,10,0,4);
		 
soc = open_sock_udp(port);
if ( ! soc ) exit(0, "Impossible to open a socket to " + port);
send(socket:soc, data:req);
r = recv(socket:soc, length:1024);
if(!r)exit(0, "No UDP answer on port " + port);
close(soc);
if((ord(r[1]) & 0x0F) == 0x02){
	set_kb_item(name:"Services/udp/l2tp", value:port);
	security_note(port:port, proto:"udp");
	}
else
	exit(1, "Got an answer on port " + port + " but received an unexpected header");
