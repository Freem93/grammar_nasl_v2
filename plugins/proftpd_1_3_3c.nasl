#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50544);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2010-3867", "CVE-2010-4221");
  script_bugtraq_id(44562);
  script_osvdb_id(68985, 68988);
  script_xref(name:"EDB-ID", value:"15449");
  script_xref(name:"Secunia", value:"42052");

  script_name(english:"ProFTPD < 1.3.3c Multiple Vulnerabilities");
  script_summary(english:"Checks version in the service banner");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

According to its banner, the version of ProFTPD installed on the
remote host is earlier than 1.3.3c. Such versions are reportedly
affected by the following vulnerabilities :

  - When ProFTPD is compiled with 'mod_site_misc' and a
    directory is writable, a user can use 'mod_site_misc'
    to create or delete a directory outside the writable
    directory, create a symlink located outside the
    writable directory, or change the time of a file
    located outside the writable directory. (Bug #3519)

  - A stack-based buffer overflow exists in the server's
    'pr_netio_telnet_gets()' function, which can be
    triggered by when reading user input containing a
    TELNET_IAC escape sequence. (Bug #3521)

Note that Nessus did not actually test for the flaws but instead has
relied on the version in ProFTPD's banner so this may be a false
positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-229/");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3519");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3521");
  # https://web.archive.org/web/20160117095522/http://www.proftpd.org/docs/RELEASE_NOTES-1.3.3c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2cebd53");
  script_set_attribute(attribute:"solution", value:"Upgrade to ProFTPD version 1.3.3c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

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
  version =~ "^1\.3\.3($|[ab]$|rc[0-9]+$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + chomp(banner) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.3c\n';
    security_hole(port:port, extra:report);
    exit(0);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The ProFTPD server on port "+port+" is not affected.");
