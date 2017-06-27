#
# (C) Tenable Network Security, Inc.
#

# Ref (for the MITM attack) :
#  To: bugtraq@securityfocus.com
#  Subject: Microsoft Terminal Services vulnerable to MITM-attacks.
#  From: Erik Forsberg <forsberg+btq@cendio.se>
#  Date: 02 Apr 2003 00:05:44 +0200
#


include("compat.inc");

if (description)
{
 script_id(10940);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2014/06/06 18:38:43 $");

 script_name(english:"Windows Terminal Services Enabled");
 script_summary(english:"Connects to the remote terminal server");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has Terminal Services enabled.");
 script_set_attribute(attribute:"description", value:
"Terminal Services allows a Windows user to remotely obtain a graphical
login (and therefore act as a local user on the remote host).

If an attacker gains a valid login and password, this service could be
used to gain further access on the remote host.  An attacker may also
use this service to mount a dictionary attack against the remote host
to try to log in remotely.

Note that RDP (the Remote Desktop Protocol) is vulnerable to
Man-in-the-middle attacks, making it easy for attackers to steal the
credentials of legitimate users by impersonating the Windows server.");
 script_set_attribute(attribute:"solution", value:
"Disable Terminal Services if you do not use it, and do not allow this
service to run across the Internet.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("find_service2.nasl");
 script_require_ports(3389);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

port = 3389;
if(!get_port_state(port)) exit(0, "Port 3389 is closed");
soc = open_sock_tcp(port, transport:ENCAPS_IP,timeout:60);
if(!soc)exit(0, "Could not open a connection to port 3389");
send(socket:soc, data:
    # TPKT Header [T.123]
    '\x03' + # version number (always 0000 0011)
    '\x00' + # reserved (always 0)
    '\x00\x13' + # Length (including header) - big endian

    # Connection request TPDU
    '\x0e' + # LI (length indicator)
    '\xe0' + # CR (1110) + CDT (0000 = class 0 or 1)
    '\x00\x00' + # DST REF (always 0)
    '\x00\x00' + # SRC REF
    '\x00' + # Class option (class 0)

    # RDP negotiation request
    '\x01' + # Type (must be 1)
    '\x00' + # Flags (must be 0)
    '\x08\x00' + # Length (must be 8) - little endian
    mkdword(0) # Requested protocols (0 = standard)
  );

r = recv(socket:soc, length:11, timeout:60); # Long timeout
if(!r)exit(1, "The remote service did not answer or shut the connection down");
if(ord(r[0]) != 0x03) exit(1, "The remote service sent an unexpected answer");
security_note(port);
register_service(port:port, proto:"msrdp");
close(soc);
