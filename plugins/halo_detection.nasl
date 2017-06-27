#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12117);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/02/15 02:47:03 $");

  script_name(english:"HALO Network Server Detection");
  script_summary(english:"Detects HALO Tournament Server");

  script_set_attribute(attribute:"synopsis", value:"A game server has been detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of HALO Network Server.  The
server is used to host Internet and Local Area Network (LAN) games.");
  script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port.

Also, ensure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

  script_family(english:"Service detection");

  script_require_keys("Settings/ThoroughTests");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (!thorough_tests) audit(AUDIT_THOROUGH);

# start script
port = 2302;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

sock = open_sock_udp(port);
if (!sock) audit(AUDIT_SOCK_FAIL, port, "UDP");

send (socket:sock, data:raw_string(0x5C, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5C) );

r = recv(socket:sock, length:512, timeout:3);

if ( ! r ) audit(AUDIT_RESP_NOT, port, 'a request', 'UDP', code:0);

# OK, there are two modes...mode 1 is when the server is actively serving up a game
# in which case you'll get a long verbose reply from the server
# in mode 2, the server is in IDLE state and is not actively serving a game
# in mode 2, the server will just send back a quick 5 byte error msg to client

# mode 1
if (egrep(string:r, pattern:"hostname.*gamever.*maxplayers")) {
    security_note(port:port, proto:"udp");
}

# mode 2
if ( (strlen(r) == 5) && (ord(r[0]) == 0xFE) && (ord(r[0]) == 0xFE) ) security_note(port:port, proto:"udp");
