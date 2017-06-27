#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18186);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2011/03/11 21:18:08 $");
 
 script_name(english:"File Alteration Monitor daemon (famd) Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A system related service which does not need to be reachable from the
network is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The File Alteration Monitor daemon (famd) is running on this port. 
This service does not need to be reachable from the outside, it is
therefore recommended that reconfigure it to disable network access." );
 script_set_attribute(attribute:"solution", value:
"Start famd with the '-L' option or edit /etc/fam.conf and set the option
'local_only' to 'true' and restartd the famd service. 

Alternatively, you may wish to filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"Low" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Detect the File Alteration Monitor daemon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports("Services/unknown");
 script_dependencies("find_service2.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');
include('network_func.inc');

if ( ! thorough_tests || get_kb_item("global_settings/disable_service_discovery")  )exit(0);

# :::FAMD
# 00: 00 00 00 10 2f 74 6d 70 2f 2e 66 61 6d 52 48 61    ..../tmp/.famRHa
# 10: 46 4c 4c 00                                        FLL.

a = get_host_ip();
# Do not use islocalhost, famd is supposed to be listening on 127.0.0.1
# only, not an external interface
local = (a =~ "^0*127\.[0-9]+\.[0-9]+\.[0-9]+$");
lan = local || is_private_addr(addr: a);

port = get_unknown_svc();
if (! port) exit(0);	# famd runs on any free privileged port??

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\0\0\0\x1aN0 500 500 sockmeister\00\x0a\0');
b = recv(socket: s, length: 512);
close(s);
if (isnull(b) || substr(b, 0, 2) != '\0\0\0') exit(0);
# First test triggers against HP Openview or Tibco
l = strlen(b);
if (l < 5 || b[l-1] != '\0' || ord(b[3]) != l - 4 || ord(b[4]) != '/' ) exit(0);

register_service(port: port, ipproto: 'tcp', proto: 'famd');

security_note(port);
