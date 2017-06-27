#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# References:
# Date:  Thu, 15 Mar 2001 22:30:24 +0000
# From: "The Flying Hamster" <hamster@VOM.TM>
# Subject: [SECURITY] DoS vulnerability in ProFTPD
# To: BUGTRAQ@SECURITYFOCUS.COM
#
#   Problem commands include:
#   ls */../*/../*/../*/../*/../*/../*/../*/../*/../*/../*/../*/../*
#   ls */.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/
#   ls .*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/
# 
#   Other commands of this style may also cause the same behavior; the exact
#   commands listed here are not necessary to trigger.
# 

include("compat.inc");

if (description)
{
 script_id(10634);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/02/01 22:42:30 $");

 script_bugtraq_id(6341);
 script_osvdb_id(10768);
 
 script_name(english:"ProFTPD STAT Command Remote DoS");
 script_summary(english:"Checks the version of the remote proftpd.");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a denial of service vulnerability
that is triggered when it receives a specially crafted STAT command.
A remote attacker can exploit this to cause the consumption of all
available memory.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/303007/30/0/threaded");
 script_set_attribute(attribute:"solution", value:
"If using ProFTPD, upgrade to version 1.2.2 and modify the
configuration file to include :

	DenyFilter \*.*/
	
Otherwise, contact the vendor for a solution.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

#
# The script code starts here : 
#

function test(soc, port, login, pass)
{
  local_var     pasv_port, soc2, req, code, data;
  if(! ftp_authenticate(socket: soc, user: login, pass: pass)) return;
  pasv_port = ftp_pasv(socket: soc);
  soc2 = open_sock_tcp(pasv_port, transport: get_port_transport(port));
  if (! soc2) return;

  req = 'STAT /*/*/*/*/*/*/*\r\n';
  send(socket:soc, data:req);
  code = ftp_recv_line(socket:soc);
  if(strlen(code))
    data = ftp_recv_listing(socket:soc2);
  else
  {
    close(soc2);
    return;
  }

  if("Permission denied" >!< data && "Invalid command" >!< data &&
     egrep(string:data, pattern:"/\.\./[^/]*/\.\./") )
  {
    security_hole(port);
    close(soc2);
    ftp_close(socket:soc);
    exit(0);
  }
  close(soc2);
  ftp_close(socket:soc);
  return;
}

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);

if (" ProFTPD " >!< banner) audit(AUDIT_NOT_LISTEN, 'ProFTPD', port);

vuln_proftpd_ver = egrep(pattern:"^220 ProFTPD ((1\.1\..*)|(1\.2\.(0|1)[^0-9]))", string:banner);

if (!login || safe_checks())
{
  if(vuln_proftpd_ver)
  {
    matches = eregmatch(string:banner, pattern:"ProFTPD ([0-9a-z.]+) ");
    if (!isnull(matches)) version = matches[1];
    else exit(1, "Unable to parse version number from FTP banner on port "+port+".");

    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + chomp(banner) +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 1.2.2\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_LISTEN_NOT_VULN, 'ProFTPD', port);
}
else if (report_paranoia > 1 || vuln_proftpd_ver)
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  test(soc: soc, login: login, pass: pass, port: port);
}
audit(AUDIT_LISTEN_NOT_VULN, 'ProFTPD', port);

