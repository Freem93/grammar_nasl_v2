#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99763);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/01 18:50:42 $");

  script_osvdb_id(154042);

  script_name(english:"MikroTik RouterOS HTTP Server Arbitrary Write RCE");
  script_summary(english:"Sends a crafted HTTP POST request.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The MikroTik RouterOS software running on the remote host is affected
by a flaw in its HTTP web server process due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via a specially crafted POST request, to write data to an
arbitrary location within the web server process, resulting in a
denial of service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://mikrotik.com/download/changelogs/#tab-tree_3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MikroTik RouterOS version 6.38.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english: "Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencie("mikrotik_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("MikroTik/RouterOS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

appname = "MikroTik RouterOS";

# version should always be available if the web interface is up
version = get_kb_item_or_exit("MikroTik/RouterOS/Version");
port = get_http_port(default:80, embedded:TRUE, dont_exit:FALSE);
get_kb_item_or_exit("Services/www/" + port + "/embedded");

# connect to the server
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, appname);

# If unpatched the server will accept any content length. It
# will then write the provided data at (stack_ptr - length).
# A patched server restricts the acceptable size in the
# content length field. The content length we send here is
# large enough to generate an immediate response from a
# patched server but small enough not to crash an unpatched server.
request = 'POST /scep/nessus?operation=PKIOperation HTTP/1.1\r\n' +
  'Host: ' + get_host_ip() + ':' + port + '\r\n' +
  'Content-Type: application/x-pki-message\r\n' +
  'Content-Length: 16384\r\n' +
  '\r\n' +
  'AAAA';
send(socket:soc, data:request);

# An unpatched server won't respond at all. A patched server
# will respond with a 200 OK.
resp = recv(socket:soc, length:1024);
close(soc);

if (!isnull(resp))
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);
}

report =
  '\nNessus has determined the server doesn\'t sufficiently\n' +
  'validate the SCEP server content length field.\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
