#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11566);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/12/23 19:06:01 $");

  script_name(english:"FTP Server root Directory .rhosts File Present");
  script_summary(english:"Downloads the remote .rhosts file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote anonymous FTP server has a .rhosts file set in its home
directory. An attacker may use it to determine the trust relationships
between this server and other hosts on the network.");
  script_set_attribute(attribute:"solution", value:
"Remove the .rhosts file from ~/ftp on this host.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/04");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  
  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default: 21);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

login = "anonymous";
password = "nessus@nessus.org";

# if(login == "") exit(0);

soc = open_sock_tcp(port);
if(! soc) audit(AUDIT_SOCK_FAIL, port);

if(! ftp_authenticate(socket:soc, user:login,pass:password))
{
  ftp_close(socket: soc);
  exit(1, "Cannot authenticate on port "+port+".");
}

send(socket:soc, data: 'CWD/\r\n');
a = ftp_recv_line(socket:soc);
if (isnull(a))
{
  ftp_close(socket: soc);
  exit(1, "No answer to CWD on port "+port+".");
}

pasv = ftp_pasv(socket:soc);
if (! pasv) exit(1, "PASV command failed on port "+port+".");
soc2 = open_sock_tcp(pasv);
if (! soc2) {
  ftp_close(socket: soc);
  exit(1, "Failed to open a socket on PASV port "+pasv+".");
}

send(socket:soc, data: 'RETR .rhosts\r\n');
r = ftp_recv_line(socket:soc);
content = "";
if (egrep(pattern:"^(150|425) ", string:r))
{
  content = ftp_recv_data(socket:soc2, line:r);
  debug_print('content=', content);
  # r2 = ftp_recv_line(socket:soc);
  # debug_print('r2=', r2);
}
close(soc2);
ftp_close(socket:soc);

if (strlen(content) > 0)
{
  if (report_verbosity > 0)
  {
    report = '\nThe .rhost file contains : \n' + content + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
