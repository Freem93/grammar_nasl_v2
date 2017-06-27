#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11845);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2013/02/15 02:47:03 $");

 script_name(english:"Overnet Detection");
 script_summary(english:"Determines if the remote system is running Overnet");

 script_set_attribute(attribute:"synopsis", value:"A peer-to-peer client appears to be running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote server seems to be a Overnet peer-to-peer client, which may
not be suitable for a business environment.");
 script_set_attribute(attribute:"solution", value:"Uninstall this software.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 exit(0);
}

include("audit.inc");

port = 5768;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

req = raw_string(0xE3,0x0C,0xAB,0xA3,0xD7,0x95,0x39,0xE5,0x8C,0x49,0xEA,0xAB,0xEB,0x4F,0xA5,0x50,0xB8,0xF4,0xDD,0x9A,0x3E,0xD0,0x89,0x1F,0x00);
send(socket:soc, data:req);
r = recv(socket:soc, length:256);
close(soc);

if (r) security_note(port:port, proto:"udp");
else exit(0, "The host does not appear to be running Overnet.");

