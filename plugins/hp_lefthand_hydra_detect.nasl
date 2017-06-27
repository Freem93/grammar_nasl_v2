#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64632);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/11 00:58:06 $");

  script_name(english:"HP LeftHand OS hydra Detection");
  script_summary(english:"Attempts to get info from the service");

  script_set_attribute(attribute:"synopsis", value:"A management service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"One of the network services provided by the hydra daemon was detected
on the remote host. This daemon runs on the HP LeftHand OS (formerly
SAN/iQ) and is used in products such as the HP Virtual SAN appliance.
This service is used for management and control.");
  script_set_attribute(attribute:"see_also", value:"http://h10032.www1.hp.com/ctg/Manual/c01750064.pdf");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:san/iq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 13841);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

function _hydra_read(socket)
{
  local_var data, len;

  data = recv(socket:socket, length:4, min:4);
  if (isnull(data)) return NULL;

  len = getdword(blob:data, pos:0);

  # sanity check
  if (len > 0x10000) return NULL;

  data = recv(socket:socket, length:len, min:len);
  return data;
}

function _hydra_write(socket, data)
{

  data = mkdword(strlen(data)) + data;
  return send(socket:socket, data:data);
}

if (thorough_tests)
{
  port = get_unknown_svc(13841);
  if (!port) audit(AUDIT_SVC_KNOWN);
}
else port = 13841;
if (known_service(port:port)) exit(0, 'The service listening on port ' + port + ' has already been identified.');
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# the protocol appears to require clients to send the first packet when the service is using SSL/TLS
transport = get_kb_item('Transports/TCP/' + port);
if (transport > ENCAPS_IP)
{
  req = '\x00\x07\x00\x00\x00';
  _hydra_write(socket:soc, data:req);
}

req = '\x00\x07\x00\x00\x00';

res =_hydra_read(socket:soc);
if (res != req)
{
  close(soc);
  audit(AUDIT_RESP_BAD, port);
}

_hydra_write(socket:soc, data:req);
res =_hydra_read(socket:soc);
close(soc);

if (isnull(res))
  audit(AUDIT_RESP_NOT, port);

# skip the first 10 bytes (unknown) to get the version
ver = NULL;
len = getdword(blob:res, pos:10);
if (len < 20)
  ver = substr(res, 14, 14 + len - 1);

if (isnull(ver))
  audit(AUDIT_RESP_BAD, port, 'handshake (invalid length)');

# the versions look similar to "9.5.00.1215"
if (ver !~ "^[0-9.]+$")
  audit(AUDIT_RESP_BAD, port, 'handshake (version ' + ver + ')');
else
  set_kb_item(name:'lefthand_os/' + port + '/version', value:ver);

# try to get the hostname and MAC address if possible
ascii = strstr(res, ver);
match = eregmatch(string:ascii, pattern:'[0-9]+_(.+)_([A-Fa-f0-9:]{17})');
if (match)
{
  hostname = match[1];
  mac = match[2];
}

register_service(port:port, proto:"hydra_13841");
replace_kb_item(name:"HP/LeftHandOS", value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to gather the following information :\n' +
    '\n  Software version : ' + ver;

  if (hostname)
    report += '\n  Hostname : ' + hostname;
  if (mac)
    report += '\n  MAC address : ' + mac;

  report += '\n';
  security_note(port:port, extra:report);
}
else security_note(port);

