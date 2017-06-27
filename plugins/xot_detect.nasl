#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(30122);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2011/03/11 21:18:10 $");
 script_name(english: "XOT Detection");
 script_set_attribute(attribute:"synopsis", value:
"This plugin detects XOT (X.25 over TCP)." );
 script_set_attribute(attribute:"description", value:
"The remote target is an XOT router." );
 script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc1613.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/x25.pdf" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: 'Detect XOT by sending an invalid packet');
 script_copyright(english: "This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_dependencie('find_service1.nasl', 'find_service2.nasl');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");
 script_require_ports(1998, "Services/unknown");
 exit(0);
}

# include('dump.inc');
include('global_settings.inc');
include('misc_func.inc');

if ( get_kb_item("global_settings/disable_service_discovery")) exit(0);
port = 1998;

if (! get_port_state(port)) exit(0);

# XOT is not silent: it abruptly closes the connection when it receives
# invalid data
if (silent_service(port)) exit(0);

# By the way, GET and HELP are definitely invalid. So...
b = get_unknown_banner(port: port, dontfetch: 1);
if (strlen(b) > 0) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
x25 = '\x20'		# Data for user, local ack, mod-128 seq
      			# LGCN = 0
    + '\0'		# LCN = 0 (reserved => invalid)
    + '\0'		# Data packet
    + '\0\0\0\0';	# Data

# XOT encapsulation (RFC 1613): 
# 2 bytes for version (must be 0) + 2 bytes for length of X25 packet
len = strlen(x25);
xot = raw_string(0, 0, (len >> 8), (len & 0xFF));

send(socket: soc, data: xot + x25);
# t1 = unixtime();
r = recv(socket: soc, length: 512);
# t2 = unixtime();
close(soc);
# dump(dtitle: 'XOT', ddata: r);
lenxot = strlen(r);
if (lenxot < 4) exit(0);
if (r[0] != '\0' || r[1] != '\0') exit(0);
lenx25 = (ord(r[2]) << 8) | ord(r[3]);
if (lenx25 + 4 != lenxot) exit(0);
register_service(port: port, proto: 'xot');
security_note(port);
