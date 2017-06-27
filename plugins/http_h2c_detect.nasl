#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85805);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/07 21:52:03 $");

  script_name(english:"HTTP/2 Cleartext Detection");
  script_summary(english:"Detects a server supporting h2c.");

  script_set_attribute(attribute:"synopsis", value:
"An HTTP/2 server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an HTTP server that supports HTTP/2 running
over cleartext TCP (h2c).");
  script_set_attribute(attribute:"see_also", value:"https://http2.github.io/");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7540");
  script_set_attribute(attribute:"see_also", value:"https://github.com/http2/http2-spec");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", "Services/unknown", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# check 80 and 443 by default
ports = add_port_in_list(list:get_kb_list("Services/www"), port:80);
ports = add_port_in_list(list:ports, port:443);

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  unknown_ports = get_unknown_svc_list();
  if (unknown_ports)
    ports = make_list(ports, unknown_ports);
}

ports = list_uniq(ports);

port = branch(ports);

report = NULL;
encaps = get_port_transport(port);

if (encaps && encaps > ENCAPS_IP)
  audit(AUDIT_NOT_DETECT, "Unencrypted connection", port);

if (get_kb_item("Services/www/" + port + "/working"))
{
  host = get_host_name();
  h2c = 'HEAD / HTTP/1.1\n' +
  'User-Agent: Nessus/' + NASL_LEVEL + '\n' +
  'Host: ' + host + '\n' +
  'Accept: */*\n' +
  'Upgrade: h2c\n' +
  'HTTP2-Settings: AAMAAABkAAQAAP__\n' +
  'Connection: Upgrade, HTTP2-Settings\n' +
  '\n\n';

  socket = open_sock_tcp(port);
  # sock can be zero for timeouts
  if (! socket)
    audit(AUDIT_SOCK_FAIL, port);

  send(socket:socket, data:h2c);

  res = recv(socket:socket, length:1024);

  if ("101 switching protocols" >< tolower(res))
  {
    set_kb_item(name:"http/" + port + "/h2c", value:TRUE);
    set_kb_item(name:"http/" + port + "/h2c/upgraded", value:TRUE);
    report = '\n  The server supports upgrading HTTP connections to' +
             '\n  HTTP/2 cleartext connections.\n';
  }

  close(socket);
}

# attempt to speak h2 without upgrading.
socket = open_sock_tcp(port);
if(!socket)
  audit(AUDIT_SOCK_FAIL, port);

req = raw_string(
0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 
0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 
0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a, # Magic
0x00, 0x00, 0x0c, # Length
0x04, # Type - SETTINGS
0x00, # ACK Flag
0x00, 0x00, 0x00, 0x00, # Stream ID
0x00, 0x04, # Settings - Initial window size
0x00, 0x04, 0x00, 0x00, # Window set to 262144
0x00, 0x02, # Settings - Enable PUSH
0x00, 0x00, 0x00, 0x00); # PUSH is not enabled.

settings_ack = raw_string(
0x00, 0x00, 0x00, # Length
0x04, # Type - SETTINGS
0x01, # ACK Flag
0x00, 0x00, 0x00, 0x00); # Stream ID

send(socket:socket, data:req);
res = recv(socket:socket, length:1024);
if (settings_ack >< res)
{
  replace_kb_item(name:"http/" + port + "/h2c", value:TRUE);
  set_kb_item(name:"http/" + port + "/h2c/direct", value:TRUE);
  report += '\n  The server supports direct HTTP/2 connections' +
            '\n  without encryption.\n';

  # Close the connection gracefully.
  # GOAWAY - CANCEL. This is fire and forget, server-side tears down
  # the connection.
  req = raw_string(
  0x00, 0x00, 0x08, # Length
  0x07, # Type - GOAWAY
  0x00, # Reserved
  0x00, 0x00, 0x00, 0x00, # Stream ID
  0x00, 0x00, 0x00, 0x00, # Promised Stream ID
  0x00, 0x00, 0x00, 0x08); # Error Code - CANCEL

  send(socket:socket, data:req);
}

close(socket);

if (report)
{
  if (report_verbosity > 0)
    security_note(port:port, extra:report);
  else
    security_note(port:port);
}
else
  audit(AUDIT_NOT_DETECT, "HTTP/2 cleartext (h2c)", port);

