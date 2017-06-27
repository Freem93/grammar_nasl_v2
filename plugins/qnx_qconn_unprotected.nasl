#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48354);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_name(english:"Unprotected QNX qconn Service");
  script_summary(english:"Connect to QNX qconn");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on this port." );
  script_set_attribute(attribute:"description", value:
"A QNX qconn service is running on this host. 

QNX plans to add some authentication to qconn.  Meanwhile, qconn
should be used only in development phase. 

Through this service, it is possible to upload and execute arbitrary
code on the host.  An attacker can use this service to take complete
control of the affected device." );
  script_set_attribute(attribute:"solution", value: 
"Filter incoming traffic to this port, disable the service, or contact
the device's vendor for a patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
   # http://www.qnx.com/developers/docs/6.5.0/index.jsp?topic=%2Fcom.qnx.doc.neutrino_user_guide%2Fsecurity.html
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?979f54af");
   # http://www.qnx.com/developers/docs/6.5.0/index.jsp?topic=%2Fcom.qnx.doc.neutrino_utilities%2Fq%2Fqconn.html
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?9468f6f3");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/qnx-qconn", 8000);
  exit (0);
}

include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = get_kb_item("Services/qnx-qconn");
if (! port)
{
  port = 8000;
  if (! service_is_unknown(port: port, ipproto: "tcp"))
    exit(0, "The service on port "+port+" is already known.");
}
if (! get_port_state(port)) exit(1, "Port "+port+" is closed.");

s = open_sock_tcp(port);
if (! s) exit(1, "Can't open a socket on TCP port "+port+" .");

r = telnet_negotiate(socket: s, pattern: "<qconn-broker> ");
send(socket: s, data: 'info\r\n');
r = recv(socket: s, length: 512);
if (strlen(r) == 0)
{
  close(s);
  exit(0, "No response received from the service on port "+port+".");
}

info = '';
foreach line (split(r, keep: 0))
{
  if (line !~ '^(<qconn-broker> |error linemode-or-echo-not-supported)')
    info += line + '\n';
}

if ('QCONN_VERSION=' >!< info)
{
  close(s);
  exit(0, "Bad response to the 'info' command received from the service on port "+port+".");
}

# To get running processes, send 'service sinfo' then 'get pids'
send(socket: s, data: 'service sinfo\r\n');
r = recv(socket: s, length: 128);
ps = '';
if ('OK' >< r)
{
  send(socket: s, data: 'get pids\r\n');
  r = recv(socket: s, length: 65536);
  # The response appears to be a list of 296 bytes long records
  # prefixed by a 28 bytes header.
  l = strlen(r);
  for (o = 28; o < l; o += 296)
  {
    name = substr(r, o + 0xA8, o + 295);
    i = stridx(name, '\0');
    if (i > 0)
    {
      txt = substr(name, 0, i-1);
      ps = strcat(ps, txt, '\n');
    }
  }
}
send(socket: s, data: 'bye\r\n');
close(s);

if (report_paranoia > 1 || ps)
{
  if (report_verbosity > 0)
  {
    e = '\nThe \'info\' command returned:\n\n' + info + '\n';
    if (ps) e += '\nThe list of running processes could be extracted :\n\n' + ps + '\n';
    security_hole(port: port, extra: e);
  }
  else
    security_hole(port: port);
  if (COMMAND_LINE) display(e);
}
