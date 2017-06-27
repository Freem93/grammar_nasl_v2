#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49779);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/09/14 19:48:34 $");

  script_name(english:"netsaint-statd Daemon Detection");
  script_summary(english:"Sends commands such as 'alldisks'");

  script_set_attribute(attribute:"synopsis", value:
"A system monitoring service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a netsaint-statd daemon, a system monitoring
tool designed to be integrated with Netsaint, although it can also be
used without that. 

Netsaint is not maintained any more, the project evolved to Nagios.");
  script_set_attribute(attribute:"see_also", value:"http://www.twoevils.org/files/netsaint_statd/");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port as it can reveal sensitive
information about the remote host.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1040);

  exit(0);
}



include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1040);
  if (!port) exit(0, "There are no unknown services.");
  if (silent_service(port)) exit(0, "The service listening on port "+port+" is silent."); 
}
else port = 1040;
if (known_service(port:port)) exit(0, "Service on port "+port+" is known.");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");

b = get_unknown_banner2(port: port, ipproto: "tcp", dontfetch: 1);
if (isnull(b)) exit(0, "No banner on port "+port+".");
if (b[1] == "spontaneous") exit(0, "The service listening on port "+port+" sends a spontaneous banner.");
if (! match(string: b[0], pattern: "Unknown command*"))
  exit(0, "The service listening on port "+port+" sends a banner that does not match netsaint-statd's.");
# Other banner:
# Sorry, you (192.168.1.202) are not among the allowed hosts...

# Send an "alldisks" command.
res = NULL;
soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

send(socket:soc, data: 'alldisks\r\n');
res = "";
while (line = recv_line(socket:soc, length:80))
{
  res += line;
  if ( strlen(res) > 1024*1024 )
  {
    close(soc);
    exit(0, "Bad protocol on port "+port+".");
  }
}
close(soc);

if (isnull(res))
  exit(0, "Bad protocol on port "+port+".");

# echo -ne 'alldisks\n' | ncat 127.0.0.1 1040
# (/,44)(/dev,4)(/home,18)(/raid,92)(/backup,92)(/dev/shm,0)(/chaudron,48)(/distribs,48)
#

# If it's netsaint-statd...
if (res =~ "^(\(/.*,[0-9]+\))+$")
{
  register_service(port:port, ipproto:"tcp", proto:"netsaint_statd");

  if (report_verbosity > 0)
  {
    report = 
     '\nNessus collected the following disk usage from the remote' +
     '\nnetsaint-statd daemon :\n\n'
     + res + '\n\n';
    security_note(port:port, extra:report);
  }
  else  security_note(port);
  exit(0);
}
exit(1, "Unexpected response to the 'alldisks' command received from the service listening on port "+port+".");
