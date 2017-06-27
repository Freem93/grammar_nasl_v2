#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42931);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/04/01 19:26:04 $");

  script_name(english:"Squeezebox Server CLI Detection");
  script_summary(english:"Sends a login command");

  script_set_attribute(
    attribute:"synopsis", 
    value:"A streaming audio service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service is a commandline interface for Squeezebox Server
(formerly known as SlimServer and SqueezeCenter), a streaming audio
server from Logitech to support their range of audio receivers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://wiki.slimdevices.com/index.php/CLI"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Ensure that use of this software agrees with your organization's 
acceptable use and security policies."
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/30"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9090);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(9090);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 9090;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


# Make sure the responses to GET and HELP command look right, unless we're being paranoid.
if (report_paranoia < 2)
{
  get = get_kb_banner(port: port, type: "get_http");
  if (!isnull(get) && 'GET %2F HTTP%2F1.0' >!< get) exit(0, "The response to an HTTP 'GET' request isn't from SqueezeCenter CLI.");

  help = get_kb_banner(port: port, type: "help");
  if (!isnull(help) && 'HELP\r\n' >!< help) exit(0, "The response to a 'HELP' isn't from SqueezeCenter CLI.");
}


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a 'login' command.
user = SCRIPT_NAME;
pass = rand() % 16;
req = 'login' + ' ' + user + ' ' + pass;
send(socket:soc, data:req+'\n');
res = recv_line(socket:soc, length:256);
close(soc);
if (!strlen(res)) exit(0);


# If it looks like a valid reply from the cli...
if ('login '+user+' '+'******' >< res)
{
  # Register and report the service.
  register_service(port:port, proto:"squeeze_cli");

  info = "";
  if (report_verbosity > 1)
  {
    # Collect version info.
    soc = open_sock_tcp(port);
    if (soc)
    {
      req = 'version ?';
      send(socket:soc, data:req+'\n');
      res = recv_line(socket:soc, length:4096);
      close(soc);

      if (strlen(res) && ereg(pattern:"^version [0-9].+", string:res))
      {
        ver = str_replace(find:"version ", replace:"", string:res);
        info += '  Version : ' + ver + '\n';
      }
    }
  }

  if (info)
  {
    report = '\n' +
      'Nessus collected the following information from the remote service :\n' +
      '\n' +
      info;
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
