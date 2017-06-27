#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34265);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2008-4242");
  script_bugtraq_id(31289);
  script_osvdb_id(48411);

  script_name(english:"ProFTPD Command Truncation Cross-Site Request Forgery");
  script_summary(english:"Sends a command in a long string to ProFTPD");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a cross-site request forgery attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

The version of ProFTPD running on the remote host splits an overly
long FTP command into a series of shorter ones and executes each in
turn.  If an attacker can trick a ProFTPD administrator into accessing
a specially-formatted HTML link, arbitrary FTP commands could be
executed in the context of the affected application with the
administrator's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Sep/529");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3115");
  script_set_attribute(attribute:"solution", value:
"Apply the patch included in the bug report or upgrade to the latest
version in CVS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);


# Unless we're paranoid, make sure the banner, if there is one, 
# looks like ProFTPD.
if (report_paranoia < 2)
{
  banner = get_ftp_banner(port:port);
  if (
    banner && 
    " ProFTPD" >!< banner && 
    "(ProFTPD)" >!< banner && 
    "220 FTP Server ready" >!< banner
  ) exit(0);
}


# Open socket and read the banner.
soc = open_sock_tcp(port);
if (!soc) exit(1);

s = ftp_recv_line(socket:soc);


# Send a long string ending in "HELP" and see how the server reacts.
bufsize = 1022;
max_lines = 5;
magic = SCRIPT_NAME;

c = crap(data:"/", length:(bufsize*max_lines)) + magic;
send(socket:soc, data: c + '\r\n');


# There's a problem if the server sent back an error where the "command"
# contains our magic and at least one line before that with nothing 
# but "/"s for the command.
magic = str_replace(find:"_", replace:" ", string:toupper(magic));

nlines = 0;
while (s = ftp_recv_line(socket:soc))
{
  nlines++;
  if (
    nlines > 1 && 
    ereg(pattern:string("^500 /*", magic), string:s)
  )
  {
    security_warning(port);
    break;
  }
  else if (!ereg(pattern:"^500 /+ ", string:s)) break;
}
ftp_close(socket:soc);
