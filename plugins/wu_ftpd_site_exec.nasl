#
# This script was written by Alexis de Bernis <alexisb@nessus.org>
#

# Changes by Tenable:
# - rely on the banner if we could not log in
# - changed the description to include a Solution:
# - revised plugin title, removed unrelated CVE ref (2/04/2009)
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
  script_id(10452);
  script_version("$Revision: 1.44 $");
  script_cvs_date("$Date: 2014/05/27 00:32:57 $");

  script_cve_id("CVE-2000-0573");
  script_bugtraq_id(726, 1387, 2240);
  script_osvdb_id(11805);

  script_name(english:"WU-FTPD site_exec() Function Remote Format String");
  script_summary(english:"Checks if the remote FTP server sanitizes the SITE EXEC command");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an FTP server with a remote root
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WU-FTPD hosted on the remote server does not properly
sanitize the argument of the SITE EXEC command. It may be possible for
a remote attacker to gain root access.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=96171893218000&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to WU-FTPD version 2.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WU-FTPD SITE EXEC/INDEX Format String Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2000-2014 A. de Bernis");

  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/wuftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

# Connect to the FTP server
port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
ftpport = port;
if (! soc) exit(1);

if(login)
{
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  # We are in
  c = 'SITE EXEC %p \r\n';
  send(socket:soc, data:c);
  b = recv(socket:soc, length:6);
  if(b == "200-0x") security_hole(ftpport);
  ftp_close(socket: soc);
  exit(0);
  }
  else
  {
    ftp_close(socket: soc);
    soc = open_sock_tcp(ftpport);
    if (! soc ) exit(1);
  }
}
  r = ftp_recv_line(socket:soc);
  close(soc);

  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  if(egrep(pattern:"220.*FTP server.*[vV]ersion (wu|wuftpd)-((1\..*)|(2\.[0-5]\..*)|(2\.6\.0)).*",
  	 string:r)){
	 report = "
Nessus is solely basing this finding on the version reported
in the banner, so this may be a false positive.
";
	 security_hole(port:ftpport, extra:report);
	 }

