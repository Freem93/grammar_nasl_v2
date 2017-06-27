#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(52974);
 script_version ("$Revision: 1.1 $");
 script_cvs_date("$Date: 2011/03/25 15:49:28 $");
 
 script_name(english:"Eric Cooperation Server Detection");
 script_summary(english:"Detects Eric server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a chat service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an Eric cooperation server.  Eric is a
Python IDE." );
 script_set_attribute(attribute:"see_also", value:"http://eric-ide.python-projects.org/");
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencie("find_service2.nasl");
 script_require_ports(42000, "Services/unknown");

  exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(42000);
  if (!port) exit(0);
}
else port = 42000;

if (!get_tcp_port_state(port)) exit(0, "TCP port "+port+" is closed.");
if (silent_service(port)) exit(0, "The service on port "+port+" is 'silent'.");
if (known_service(port:port)) exit(0, "The service on port "+port+" is known already.");

b = get_unknown_banner2(port: port, dontfetch: 1);
if (! isnull(b) && strlen(b[0]) > 0)
{
  foreach k (make_list("spontaneous", "get_http", "help"))
    if (b[1] == v)
      exit(0, "Eric is not running on port "+port+".");
}

s = open_sock_tcp(port);
if (! s) exit(1, "Cannot connect to TCP port "+port+".");
cmd = 'nessus:'+ (65536 - port);
len = strlen(cmd);
send(socket: s, data: 'GREETING|||'+len+'|||'+cmd);
r = recv(socket: s, length: 1024);
close(s);

if (r == cmd) exit(0, "The service on port "+port+" looks like echo.");

v = eregmatch(string: r, pattern: 
  '^GREETING\\|\\|\\|([0-9]+)\\|\\|\\|(([^:|]+):([0-9]+))$' );
if (! isnull(v))
{
  if (int(v[1]) == strlen(v[2]))
  {
    register_service(port: port, proto: 'eric-coop');
    txt = '\nEric is run by user \'' + v[3] + '\' on port '+ v[4] + '.\n';
    security_note(port:port, extra: txt);
    exit(0);
  }
}
exit(0, "Eric is not running on port "+port+".");
