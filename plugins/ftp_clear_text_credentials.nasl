#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34324);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/12/08 20:42:13 $");

 script_name(english:"FTP Supports Cleartext Authentication");
 script_summary(english:"Check if the FTP server accepts passwords in cleartext.");


 script_set_attribute(attribute:"synopsis", value:"Authentication credentials might be intercepted.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server allows the user's name and password to be
transmitted in cleartext, which could be intercepted by a network
sniffer or a man-in-the-middle attack.");
 script_set_attribute(attribute:"solution", value:
"Switch to SFTP (part of the SSH suite) or FTPS (FTP over SSL/TLS). In
the latter case, configure the server so that control connections are
encrypted.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_cwe_id(
   522,	# Insufficiently Protected Credentials
   523,	# Unprotected Transport of Credentials
   928, # Weaknesses in OWASP Top Ten 2013
   930  # OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
 );

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_starttls.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

user = get_kb_item('ftp/login');
if (strlen(user) == 0 || user == 'anonymous' || user == 'ftp')
{
  if (supplied_logins_only)  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

  user = rand_str(length:8, charset:'abcdefghijklmnopqrstuvwxyz');
}
pass = get_kb_item('ftp/password');
if (strlen(pass) == 0) pass = 'root@example.com';

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if (strlen(banner) == 0) exit(1, "No FTP banner on port "+port+".");
if (banner =~ '^[45][0-9][0-9][ -]')
 exit(1, "The FTP server on port "+port+" rejects our connections.");

trp = get_port_transport(port);
if (trp > ENCAPS_IP)
 exit(0, "The FTP server on port "+port+" is running through SSL/TLS.");

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);

b = ftp_recv_line(socket: soc);
if (b =~ '^2[0-9][0-9][ -]')
{
 u = ftp_send_cmd(socket: soc, cmd: 'USER '+user);
 if (u =~ '^3[0-9][0-9][ -]')
 {
  if (report_verbosity < 1)
  {
    if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port,
						value:"The remote FTP server allows the credentials to be transmitted in clear text.");
    security_note(port);
  }
  else
  {
   if (get_kb_item("ftp/"+port+"/starttls")) report =
'\nAlthough this FTP server supports \'AUTH TLS\', it is not mandatory
and USER and PASS may be sent without switching to TLS.';
   else report = '\nThis FTP server does not support \'AUTH TLS\'.';

   if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
   security_note(port:port, extra:report);
  }

  # Make FTPD happy
  b = ftp_send_cmd(socket: soc, cmd: 'PASS '+pass);
 }
}
ftp_close(socket: soc);
