#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18393);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2011/04/01 19:26:04 $");

 script_name(english: "Entropy Gathering Daemon (EGD) Detection");

 script_set_attribute(attribute:"synopsis", value:
"A random number generator is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The Entropy Gathering Daemon is running on the remote host.
EGD is a user space random generator for operating systems 
that lack /dev/random" );
 script_set_attribute(attribute:"see_also", value:"http://egd.sourceforge.net/" );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Detect the Entropy Gathering Daemon (EGD)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_require_ports("Services/unknown");
 script_dependencies("find_service1.nasl", "find_service2.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');

if ( ! thorough_tests || get_kb_item("global_settings/disable_service_discovery")  ) exit(0);

port = get_unknown_svc(0);
if ( ! port ) exit(0);
if (! get_port_state(port)) exit(0);

if (get_kb_banner(port: port, type: 'spontaneous') ||
    get_kb_banner(port: port, type: 'get_http') ||
    get_kb_banner(port: port, type: 'help') )
 exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\0');	# get
r = recv(socket: s, length: 16);
close(s);
if (strlen(r) != 4) exit(0);
entropy = 0;
for (i = 0; i <= 3; i ++)
 entropy = (entropy << 8) | ord(r[i]);

debug_print('entropy=', entropy, '\n');

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\x01\x07');	# Read 7 bytes of entropy
r = recv(socket: s, length: 16);
close(s);
n = ord(r[0]);
if (strlen(r) != n + 1) exit(0);
debug_print('EGD gave ', n, 'bytes of entropy (7 requested)\n');

register_service(port: port, proto: 'egd');
security_note(port);
