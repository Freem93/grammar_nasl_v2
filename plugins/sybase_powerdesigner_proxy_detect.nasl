#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50704);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"Sybase PowerDesigner Repository Proxy Detection");
  script_summary(english:"Checks for Sybase PowerDesigner Repository Proxy");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running a database proxy service.");
  
  script_set_attribute(attribute:"description", value:
"The remote service is a Sybase PowerDesigner Repository Proxy, which
allows users to issue SQL statements via an ODBC connection to be
executed on the database server.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c268aa2c");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6eca17bc");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 32999);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


global_var port;

if (thorough_tests && !get_kb_item('global_settings/disable_service_discovery'))
{
  port = get_unknown_svc(32999);
  if (!port) exit(0, 'get_unknown_svc() failed.');
  if (!silent_service(port)) exit(0, 'The service on port '+port+' isn\'t silent.');
}
else port = 32999;
if (known_service(port:port)) exit(0, 'The service listening on TCP port '+port+' is already known.');
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");


# Sends a command to server and returns the response (minus the 'header');
# exits if anything unexpected was encountered.
function exec()
{
  local_var soc, cmd, res, match, code, length;
  soc = _FCT_ANON_ARGS[0];
  cmd = _FCT_ANON_ARGS[1];

  send(socket:soc, data:cmd + '\n');
  res = recv_line(socket:soc, length:32);
  if (isnull(res)) exit(0, 'No response was received from port '+port+'.');
  match = eregmatch(string:res, pattern:'^([0-9]+)( ([0-9]+))?$');
  if (isnull(match)) exit(0, 'The response from port '+port+' does not appear to be from a Sybase PowerDesigner Repository Proxy.');

  code = match[1];
  length = match[3];

  if (code != 0) exit(1, 'Unexpected return code (' + code + ') received from port '+port+'.');
  if (isnull(length)) return code; # some commands only return a status code

  res = recv(socket:soc, length:length, min:length);
  if (strlen(res) != length) exit(1, 'Error reading data from port '+port+'.');

  return res;
}


soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+"."); 

# Try to get the version, and run an additional command that indicates
# we're probably looking at the right software
ver = exec(soc, 'VERSION');
if (ver !~ '^[0-9.]+$') exit(1, '"' + ver + '" doesn\'t look like a version number.');
pxyver = exec(soc, 'PXYVERSION');  # this var is never used, the call is only made to verify it's a recognized cmd

register_service(port:port, ipproto:"tcp", proto:"sybase_powerdesigner_proxy");
set_kb_item(name:"sybase_powerdesigner_proxy/version", value:ver);

if (report_verbosity > 0)
{
  report = 
  '\n  Version : ' + ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port:port, proto:"tcp");

exec(soc, 'CLOSE');
close(soc);
