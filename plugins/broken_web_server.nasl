#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(34474);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/02/26 19:45:00 $");

  script_name(english:"Broken Web Server Detection");
  script_summary(english:"Checks that the web server is working correctly and quickly.");

  script_set_attribute(attribute:"synopsis", value:
"Tests on this web server have been disabled.");
  script_set_attribute(attribute:"description", value:
"The remote web server seems password protected or misconfigured.  

Further tests on it will be disabled so that the whole scan is not
slowed down.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"N/A");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

timeout = get_read_timeout();

port = get_kb_item("Services/www");
# Do not add default ports here. This script must only run on identified
# web servers.
if (!port) exit(0, "Nessus did not detect any web servers on the host.");

if (! get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if ( get_kb_item("Services/www/"+port+"/broken") ||
     get_kb_item("Services/www/"+port+"/working") ) exit(0);

starttime = unixtime();
r = http_send_recv3(port: port, method: 'GET', item: '/', version: 11, no_body: 1);

if (isnull(r))
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    close(soc);
    declare_broken_web_server(port: port,
     reason:'The server did not answer to a \'GET\' HTTP request.');
  }
  else
  {
    declare_broken_web_server(port: port,
     reason: strcat('TCP port ', port, ' appears closed or filtered now.'));
  }
  exit(0);
}

endtime = unixtime();

delay = endtime - starttime;
if (delay > 2 * timeout)
{
 declare_broken_web_server( port: port,
  reason: 'The web server took '+delay+' seconds to read /');
  exit(0);
}
if (r[0] =~ '^HTTP/[0-9.]+ 503 ')
{
  declare_broken_web_server(port: port,
   reason: 'The server answered with a 503 code (overloaded).');
  exit(0);
}

if (r[0] =~ '^HTTP/[0-9.]+ +403 ' && delay >= timeout)
{
  declare_broken_web_server(port: port,
   reason: 'The server took '+delay+' seconds to send back a 403 code on /');
  exit(0);
}

if ("HTTP" >!< r[0])
{
 str = chomp(r[0]);
  declare_broken_web_server(port: port,
   reason: 'The server appears to speak HTTP/0.9 only.');
  exit(0);
}

if (port == 5000 && r[0] =~ "^HTTP/[0-9.]+ +400 ")
{
  declare_broken_web_server(port: port,
    reason: 'The web server returned a 400 code on port 5000.');
  exit(0);
}
set_kb_item(name: "Services/www/" +port+ "/working", value: TRUE);
