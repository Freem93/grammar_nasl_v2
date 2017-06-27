#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46212);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/10/06 14:05:58 $");

  script_name(english:"Tenable PVS Proxy Detection");
  script_summary(english:"Checks if the server reports it's an NTP proxy");

  script_set_attribute(attribute:"synopsis", value:"A proxy service is listening on this port.");
  script_set_attribute(attribute:"description", value:
"The remote service appears to be a Tenable Network Security proxy for
either the Tenable Passive Vulnerability Scanner (PVS) or the Tenable
Security Center 3 proxy.

PVS monitors network traffic in real-time, detecting server and client
vulnerabilities, and a PVS proxy is used by Tenable's SecurityCenter 4
to transfer report data between a PVS sensor and a SecurityCenter
console.

The Security Center 3 proxy is for legacy communication requirements.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/products/passive-vulnerability-scanner");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:pvs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/unknown", "Services/www", 8835, 1243);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# PVS >= 4.0
version = NULL;
install = NULL;

port = get_http_port(default:8835, dont_exit:TRUE);
if (!isnull(port))
{
  server_header = http_server_header(port:port);
  if ('PVS Web Server' >< server_header)
  {
    version = NULL;
    res = http_send_recv3(method:"GET", item:'/feed', port:port);
    if (!isnull(res))
    {
      if ('<server_version>' >< res[2])
      {
        version = strstr(res[2], '<server_version>') - '<server_version>';
        version = version - strstr(version, '</server_version>');
      }
      install = add_install(appname:'pvs', ver:version, port:port, dir:'/');
    }
  }
}
if (!isnull(install))
{
  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'PVS',
      installs:install,
      port:port,
      item:'/'
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

# PVS < 4.0
if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1243);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (silent_service(port)) audit(AUDIT_SVC_SILENT, port);
}
else port = 1243;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (known_service(port:port)) audit(AUDIT_SVC_ALREADY_KNOWN, port);
if (get_port_transport(port) == ENCAPS_IP) exit(0, "The service listening on "+port+" does not encrypt traffic.");


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# Send an NTP message asking if it's a proxy.
req = '< NTP/1.2 >< is_proxy >\n';
send(socket:soc, data:req);
res = recv_line(socket:soc, length:1024);
if (strlen(res) == 0) audit(AUDIT_RESP_NOT, port);

if (req == res)
{
  res = recv(socket:soc, length:7);
  if (strlen(res) && "User : " >< res)
  {
    # Register and report the service.
    register_service(port:port, proto:"pvs_proxy");
    security_note(port);

    close(soc);
    exit(0);
  }
}
close(soc);
exit(0, "The response from the service listening on port "+port+" does not look like PVS Proxy.");
