#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51366);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2010-4652");
  script_bugtraq_id(44933);
  script_osvdb_id(70782);

  script_name(english:"ProFTPD < 1.3.3d 'mod_sql' Buffer Overflow");
  script_summary(english:"Checks version in the service banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a heap-based buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

According to its banner, the version of ProFTPD installed on the
remote host is earlier than 1.3.3d. Such versions are reportedly
affected by a heap-based buffer overflow vulnerability in the function
'sql_prepare_where()' in the file 'contrib/mod_sql.c'. An
unauthenticated, remote attacker may be able to exploit this in
combination with an earlier SQL injection vulnerability
(CVE-2009-0542) to execute arbitrary code with root privileges.

Note that Nessus did not actually test for the flaw but instead has
relied on the version in ProFTPD's banner.");
  script_set_attribute(attribute:"see_also", value:"http://phrack.org/issues.html?issue=67&id=7#article");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3536");
  # https://web.archive.org/web/20150722015528/http://www.proftpd.org/docs/RELEASE_NOTES-1.3.3d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43c39fae");
  script_set_attribute(attribute:"solution", value:"Upgrade to ProFTPD version 1.3.3d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/proftpd", "Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) exit(1, "Unable to obtain FTP banner on port "+port+".");
if ("ProFTPD" >!< banner) exit(1, "The FTP service on port "+port+" does not appear to be ProFTPD.");

matches = eregmatch(string:banner, pattern:"ProFTPD ([0-9a-z.]+) ");
if (!isnull(matches)) version = matches[1];
else exit(1, "Unable to obtain version number from FTP banner on port "+port+".");

if (
  version =~ "^0\." ||
  version =~ "^1\.[0-2]\." ||
  version =~ "^1\.3\.[0-2]($|\.|[^0-9])" ||
  version =~ "^1\.3\.3($|[abc]$|rc[0-9]+$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + chomp(banner) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.3d\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "ProFTPD version "+version+" is running on port "+port+" and hence is not affected.");
