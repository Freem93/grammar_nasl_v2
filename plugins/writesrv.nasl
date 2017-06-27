#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11222);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2011/03/11 21:52:41 $");
 
  script_name(english:"writesrv Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"writesrv is running on this port.  it is used to send messages to
users." );
 script_set_attribute(attribute:"description", value:
"This service gives potential attackers information about who is
connected and who isn't, easing social engineering attacks for
example." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you don't use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Detect writesrv");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 # script_dependencies("find_service1.nasl");
 script_require_ports(2401);
 exit(0);
}

#


# port = get_kb_item("Services/unknown");
port = 2401;	# Yes! Just like cvspserver!

if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit (0);

m1 = "NESSUS" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
l0 = raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
m2 = "root" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

m = m1 + l0;
for (i=2; i < 32; i=i+1) m = m + l0;
m = m + m2;
for (i=2; i < 32; i=i+1) m = m + l0;

m = m + raw_string(0x2e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, l0);
#display(m) ; exit(0);
send(socket: s, data: m);
r = recv(socket: s, length: 1536);
#display(r);

len = strlen(r);
if (len < 512) exit(0);	# Can 'magic read' break this?

# It seems that the answer is split into 512-bytes blocks padded 
# with nul bytes:
# <digit> <space> <digit> <enough bytes...>
# Then, if the user is logged:
# <ttyname> <nul bytes...>
# And maybe another block
# <tty2name> <nul bytes...>

for (i = 16; i < 512; i = i + 1)
{
  if (ord(r[i]) != 0) exit(0);
}

security_note(port);
