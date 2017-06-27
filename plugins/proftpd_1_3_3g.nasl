#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56956);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2011-4130");
  script_bugtraq_id(50631);
  script_osvdb_id(77004);

  script_name(english:"ProFTPD < 1.3.3g / 1.3.4 Response Pool Use-After-Free Code Execution");
  script_summary(english:"Checks version in the service banner");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

According to its banner, the version of ProFTPD installed on the
remote host is earlier than 1.3.3g or 1.3.4. As such, it is
potentially affected by a code execution vulnerability due to how the
server manages the response pool that is used to send responses from
the server to the client. A remote, authenticated attacker could could
leverage this issue to execute arbitrary code on the remote host,
subject to the privileges of the user running the affected
application.

Note that Nessus did not actually test for the flaw but instead has
relied on the version in ProFTPD's banner.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-328/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Nov/174");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3711");
  # https://web.archive.org/web/20150914195742/http://www.proftpd.org/docs/NEWS-1.3.3g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4b46de4");
  # https://web.archive.org/web/20150621164000/http://www.proftpd.org/docs/NEWS-1.3.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c33326d");
  script_set_attribute(attribute:"solution", value:"Upgrade to ProFTPD version 1.3.3g / 1.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

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

if (version =~ '^1(\\.3)?$') exit(1, "The banner from ProFTPD listening on port "+port+" - "+banner+" - is not granular enough.");

if (
  version =~ "^0\." ||
  version =~ "^1\.[0-2]\." ||
  version =~ "^1\.3\.[0-2]($|\.|[^0-9])" ||
  version =~ "^1\.3\.3($|[a-f]$|rc[0-9]+$)" ||
  version =~ "^1\.3\.4($|rc[0-9]+$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + chomp(banner) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.3g / 1.3.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The ProFTPD "+version+" install listening on port "+port+" is not affected.");
