#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66360);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/09 18:03:23 $");

  script_name(english:"Nagios NRPE Plugin Detect");
  script_summary(english:"Sends command '_CHECK_NRPE'");

  script_set_attribute(attribute:"synopsis", value:
"A monitoring service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The Nagios Remote Plugin Executor (NRPE) was detected on the remote
host.  This application allows a user to execute Nagios plugins and
monitor remote machines.");
  script_set_attribute(attribute:"solution", value:"n/a");
  # http://exchange.nagios.org/directory/Addons/Monitoring-Agents/NRPE--2D-Nagios-Remote-Plugin-Executor/details
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18b803b6");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 5666);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssh1_func.inc");

function calculate_crc32(data)
{
  local_var crc, i, len;
  len = strlen(data);
  crc = 0xFFFFFFFF;
  for (i=0; i<len; i++)
    crc = ((crc >>> 8) & 0x00FFFFFF) ^ crc32tab[(crc ^ ord(data[i])) & 0xFF];
  return crc ^ 0xFFFFFFFF;
}

appname = "Nagios NRPE";

# default listening port
port_list = make_list(5666);

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  unknown_services = get_kb_list("Services/unknown");
  if (!isnull(unknown_services))
    port_list = make_list(port_list, unknown_services);
}

# filter out duplicate ports
port_list = list_uniq(port_list);

# For each of the ports we want to try, fork.
port = branch(port_list);

if (known_service(port:port)) exit(0, "The service listening on port " + port + " is already known.");
  if (!port) audit(AUDIT_SVC_KNOWN);

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

s = open_sock_tcp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port,'TCP');

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

packet_version = '\x00\x02';
packet_type    = '\x00\x01';
crc            = '\x00\x00\x00\x00';
result_code    = mkbyte(rand() % 255) + mkbyte(rand() % 255);
cmd            = '_NRPE_CHECK';
buffer = '';

buffer += crap(data:'\x00', length: (1024 - strlen(cmd)));

random_buffer = mkbyte(rand() % 255) + mkbyte(rand() % 255);

pkt = packet_version + packet_type + crc + result_code + cmd + buffer + random_buffer;

crc =  uint(calculate_crc32(data:pkt));
crc =
  mkbyte(crc >> 24) +
  mkbyte(crc >> 16) +
  mkbyte(crc >> 8) +
  mkbyte(crc >> 0);

pkt = packet_version + packet_type + crc + result_code + cmd + buffer + random_buffer;

send(socket:s, data:pkt);

res = recv(socket:s, length:10, min:10);
if (strlen(res) == 0)
{
  close(s);
  audit(AUDIT_RESP_NOT, port);
}

if (strlen(res) != 10)
{
  close(s);
  exit(0, 'Unexpected response size for service on port ' + port + '.');
}

recv_version     = substr(res, 0, 1);
recv_pkt_type    = substr(res, 2, 3);
recv_crc         = substr(res, 4, 7);
recv_result_code = substr(res, 8, 9);

if (recv_version  != '\x00\x02')
{
  close(s);
  exit(0, 'Unrecognized protocol version for service on port ' + port + '.');
}

if (recv_pkt_type != '\x00\x02')
{
  close(s);
  exit(0, 'Unrecognized packet type for server on port ' + port + '.');
}

data = recv(socket:s, length:1024, min:1024);
if (strlen(data) == 0)
{
  close(s);
  audit(AUDIT_RESP_NOT, port);
}

if ("NRPE" >!< data) audit(AUDIT_NOT_DETECT, appname, port);

if (strlen(data) != 1024)
{
  close(s);
  exit(0, 'Unexpected response size for service on port ' + port + '.');
}

rand_bytes = recv(socket:s, length:2, min:2);

close(s);

if (strlen(rand_bytes) == 0) audit(AUDIT_RESP_NOT, port);

if (strlen(rand_bytes) != 2)
  exit(0, 'Unexpected response size for service on port ' + port + '.');

recv_pkt = recv_version + recv_pkt_type + '\x00\x00\x00\x00' +
           recv_result_code + data + rand_bytes;

calculated_crc = uint(calculate_crc32(data:recv_pkt));
calculated_crc =
  mkbyte(calculated_crc >> 24) +
  mkbyte(calculated_crc >> 16) +
  mkbyte(calculated_crc >> 8) +
  mkbyte(calculated_crc >> 0);

if (recv_crc != calculated_crc)
  exit(0, 'CRC check failed for service on port ' + port + '.');

version = "unknown";
value = eregmatch(pattern:"NRPE v([0-9.]+(b\d+)?)", string:data);
if (!isnull(value)) version = value[1];

set_kb_item(name:"nrpe/" + port + "/Version", value:version);

register_service(port:port, ipproto:"tcp", proto:"nrpe");

version_src = str_replace(find:'\0', replace:'', string:data);

if (report_verbosity > 0)
{
    report =
        '\n  Source  : ' + version_src +
        '\n  Version : ' + version +
        '\n';
    security_note(port:port,extra:report);
}
else security_note(port);
