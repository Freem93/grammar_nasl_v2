#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73757);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/03/09 01:31:02 $");

  script_cve_id("CVE-2014-2913");
  script_bugtraq_id(66969);
  script_osvdb_id(106007);
  script_xref(name:"EDB-ID", value:"32925");
  script_xref(name:"EDB-ID", value:"34461");

  script_name(english:"Nagios NRPE Command Argument Processing Enabled");
  script_summary(english:"Checks if the remote Nagios NRPE server allows command argument processing containing newline.");

  script_set_attribute(attribute:"synopsis", value:
"The monitoring service running on the remote host may be affected by
an arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Nagios Remote Plugin Executor (NRPE) running on the
remote host has command argument processing enabled and accepts the
newline character. An unauthenticated, remote attacker can exploit
this issue to execute arbitrary commands within the context of the
vulnerable application by appending those commands via a newline
character in the '-a' option to libexec/check_nrpe.");
  script_set_attribute(attribute:"see_also", value:"http://legalhackers.com/advisories/nagios-nrpe.txt");
  # http://packetstormsecurity.com/files/126211/Nagios-Remote-Plugin-Executor-2.15-Remote-Command-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd566434");
  script_set_attribute(attribute:"solution", value:
"Disable command argument processing in the NRPE configuration.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("nagios_nrpe_detect.nasl");
  script_require_ports("Services/nrpe");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
# ssh1_func.inc is required for crc32tab[] look up table below
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

port = get_service(svc:"nrpe", exit_on_fail:TRUE);

appname = "Nagios NRPE";

version = get_kb_item_or_exit("nrpe/" + port + "/Version");

s = open_sock_tcp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port,'TCP');

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

packet_version = '\x00\x02';
packet_type    = '\x00\x01';
crc            = '\x00\x00\x00\x00';
result_code    = mkbyte(rand() % 255) + mkbyte(rand() % 255);
cmd            = '_NRPE_CHECK!nessus';
buffer = '\x0a';

buffer += crap(data:'\x00', length: (1024 - strlen(cmd) - 1));

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

# when command argument processing is disabled, the server will not respond at all
if (strlen(res) == 0)
{
  close(s);
  audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
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

# if we get a proper response, we are vuln
security_report_v4(
  port:port,
  severity:SECURITY_HOLE,
  extra:report_items_str(report_items:make_array(
    "Version", version,
    "NRPE command argument processing", "Enabled"
  ))
);
