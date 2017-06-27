#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65188);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/03 11:06:12 $");

  script_cve_id("CVE-2013-2278");
  script_bugtraq_id(58182);
  script_osvdb_id(90643);

  script_name(english:"War FTP Daemon 1.82 Denial of Service");
  script_summary(english:"Checks version in the service banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of War FTP Daemon installed on the
remote host is 1.82.  As such, it is potentially affected by a flaw in
how log messages are logged to the Windows Event log.  A remote,
unauthenticated attacker could leverage this issue to cause a denial of
service. 

Note that Nessus did not actually test for the flaw but instead has
relied on the version in War FTP Daemon's banner.");
  script_set_attribute(attribute:"see_also", value:"http://www.warftp.org/?menu=323&cmd=show_article&article_id=1035");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Feb/142");
  script_set_attribute(attribute:"solution", value:"Upgrade to War FTP Daemon version 1.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jgaa:warftpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "War FTP Daemon";

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("WarFTPd" >!< banner) audit(AUDIT_NOT_DETECT, appname, port);

banner = NULL;
version = NULL;
foreach line (split(banner, keep:FALSE))
{
  match = eregmatch(string:line, pattern:"\s?(WarFTPd ([0-9a-z.\-RC]+).*)");
  if (!isnull(match))
  {
    banner = match[1];
    version = match[2];
    break;
  }
}
if (isnull(version)) audit(AUDIT_SERVICE_VER_FAIL, appname, port);

if (version =~ "^1\.82($|[^0-9]+)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + chomp(banner) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.83\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
