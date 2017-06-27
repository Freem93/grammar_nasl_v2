#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47040);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/22 21:25:22 $");

  script_bugtraq_id(40320);
  script_osvdb_id(64869);
  script_xref(name:"Secunia", value:"39856");

  script_name(english:"Solaris FTP Daemon Long Command XSRF");
  script_summary(english:"Attempts to run a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a cross-site request forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FTP running on the remote host is affected by a
cross-site request forgery vulnerability. Long file names are not
processed properly, resulting in the execution of arbitrary commands. 

If a user is logged into the FTP server via web browser, a remote
attacker could exploit this by tricking them into requesting a
maliciously crafted web page, resulting in the execution of arbitrary
FTP commands.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/282");
  script_set_attribute(attribute:"see_also", value:"https://cxsecurity.com/issue/WLB-2010050127");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/05/21");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_ftp_port(default:21);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

user = get_kb_item('ftp/login');
pass = get_kb_item('ftp/password');
if (isnull(user))
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  user = 'anonymous';
}
if (isnull(pass))
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  pass = 'nessus@' + get_host_name();
}

if (!ftp_authenticate(socket:soc, user:user, pass:pass))
{
  close(soc);
  exit(1, 'Authentication failed for user "'+user+'" on port '+port+'.');
}

send(socket:soc, data:'PWD\r\n');
r = recv_line(socket:soc, length:4096);

cmd = SCRIPT_NAME+'-'+unixtime();
csrf = 'SIZE ' + crap(data:'/', length:2042) + cmd + '\r\n';
send(socket:soc, data:csrf);
r = recv_line(socket:soc, length:4096);
if (!strlen(r)) audit(AUDIT_RESP_NOT, port);

send(socket:soc, data:csrf);
r = recv_line(socket:soc, length:4096);
if (!strlen(r)) audit(AUDIT_RESP_NOT, port);

close(soc);

if (tolower(cmd) >< tolower(r) && 'command not understood' >< r)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  security_warning(port);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
