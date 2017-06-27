#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79388);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/24 19:10:27 $");

  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_bugtraq_id(71178, 71242);
  script_osvdb_id(114929, 114930);

  script_name(english:"ClamAV < 0.98.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the response to a clamd VERSION command.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus service running on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon on the
remote host is prior to 0.98.5. It is, therefore, potentially affected
by the following vulnerabilities :

  - An error exists related to using the 'clamscan -a'
    command to scan certain JavaScript files that could
    cause the application to crash. (CVE-2013-6497)

  - Errors exist related to scanning maliciously crafted
    Yoda's Crypter files that could cause a heap-based
    buffer overflow or an application crash.
    (CVE-2014-9050)");
  # ChangeLog / README Commit
  # https://github.com/vrtadmin/clamav-devel/commit/2f578ecb5831cfb7931ec3d043e8cab33c595da9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b76f60c");
  # https://github.com/vrtadmin/clamav-devel/commit/fc3794a54d2affe5770c1f876484a871c783e91e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?753993b1");
  # Release blog
  script_set_attribute(attribute:"see_also", value:"http://blog.clamav.net/2014/11/clamav-0985-has-been-released.html");
  # Bug for CVE-2013-6497
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=11088");
  # Bug for CVE-2014-9050 (requires authentication to view as of 2014 Nov 24)
  # script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=11155");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q4/752");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.98.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 0.x < 0.98.5
# 0.98.5beta\d
# 0.98.5rc\d
if (
  (ver[0] == 0 && ver[1] < 98) ||
  (ver[0] == 0 && ver[1] == 98 && ver[2] < 5) ||
  version =~ "^0\.98\.5-(beta|rc)\d($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.98.5' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
