#
# (C) Tenable Network Security, Inc.
#
# See RFC 1771
#


include("compat.inc");

if(description)
{
  script_id(11907);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2011/03/11 21:18:07 $");

  script_name(english:"BGP Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a BGP (Border Gatway Protocol) service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BGP, a popular routing protocol.  This
indicates that the remote host is probably a network router." );
 script_set_attribute(attribute:"solution", value:
"If the remote service is not used, disable it.  Otherwise, make sure that access
to this service is either filtered so that only allowed hosts can
connect to it, or that TCP MD5 is enabled to protect this service from
rogue connections." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/25");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  summary["english"] = "Sends a BGP Hello packet";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_require_ports(179);
  exit(0);
}

##include("dump.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 179;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

s = this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);
for (i = 1; i <=4; i++) a[i] = int(v[i]);

r = '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'; # Marker
r += raw_string(0, 45,	# Length
		1,	# Open message
		4, 	# Version
		rand() % 256, rand() % 256,	# My AS
		0, 180,	# Hold time
		a[1], a[2], a[3], a[4],	# BGP identifier
		0, 	# Optional parameter length
		2, 6, 1, 4, 0, 1, 0, 1,
		2, 2, 80, 0,
		2, 2, 2, 0	);

send(socket: soc, data: r);

r = recv(socket: soc, length: 16, min: 16);
if ( strlen(r) < 16 ) exit(0);

for (i = 0; i < 16; i ++)
  if (ord(r[i]) != 0xFF)
    break;
if (i < 16) exit(0);		# Bad marker

r = recv(socket: soc, length: 2, min: 2);
len = ord(r[0]) * 256 + ord(r[1]);
len -= 18;
if (len <= 0) exit(0);
r = recv(socket: soc, length: len, min: len);
if ( strlen(r) != len ) exit(0);
##dump(ddata: r, dtitle: "BGP");
type = ord(r[0]);

if (type == 1)	# Hello
{
  ver = ord(r[1]);
  as = 256 * ord(r[2]) + ord(r[3]);
  ht = 256 * ord(r[4]) + ord(r[5]);	# Hold time
}
#else if (type == 3)	# Notification - may be error

register_service(port: port, proto: "bgp");
security_note(port);

