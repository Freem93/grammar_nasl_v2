#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62213);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2011-3026",
    "CVE-2011-3048",
    "CVE-2011-3368",
    "CVE-2011-3389",
    "CVE-2011-3607",
    "CVE-2011-4317",
    "CVE-2011-4599",
    "CVE-2012-0021",
    "CVE-2012-0031",
    "CVE-2012-0053",
    "CVE-2012-0650",
    "CVE-2012-0668",
    "CVE-2012-0670",
    "CVE-2012-0671",
    "CVE-2012-0831",
    "CVE-2012-1172",
    "CVE-2012-1173",
    "CVE-2012-1667",
    "CVE-2012-1823",
    "CVE-2012-2143",
    "CVE-2012-2311",
    "CVE-2012-2386",
    "CVE-2012-2688",
    "CVE-2012-3719",
    "CVE-2012-3722"
  );
  script_bugtraq_id(
    47545,
    49778,
    49957,
    50494,
    50802,
    51006,
    51407,
    51705,
    51706,
    51954,
    52049,
    52830,
    52891,
    53388,
    53403,
    53579,
    53582,
    53584,
    53729,
    53772,
    54638,
    56240,
    56241
  );
  script_osvdb_id(
    72399,
    74829,
    76046,
    76079,
    76744,
    77310,
    77698,
    78293,
    78555,
    78556,
    79017,
    79294,
    80822,
    81025,
    81633,
    81791,
    81939,
    81941,
    81942,
    82510,
    82609,
    84126,
    85644,
    85648,
    85649
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-09-19-2");
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2012-004) (BEAST)");
  script_summary(english:"Check for the presence of Security Update 2012-004.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.6 that does not
have Security Update 2012-004 applied. This update contains multiple
security-related fixes for the following components :

  - Apache
  - Data Security
  - DirectoryService
  - ImageIO
  - International Components for Unicode
  - Mail
  - PHP
  - QuickLook
  - QuickTime
  - Ruby"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-185/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Nov/111");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5501");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00004.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2012-004 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.6");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
if (
  egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2012\.00[4-9]|201[3-9]\.[0-9]+)(\.snowleopard[0-9.]*)?\.bom", string:packages) ||
  egrep(pattern:"^com\.apple\.pkg\.update\.security\.2012\.004(\.snowleopard)?\.1\.0\.bom", string:packages)
) exit(0, "The host has Security Update 2012-004 or later installed and is therefore not affected.");
else
{
  if (report_verbosity > 0)
  {
    security_boms = egrep(pattern:"^com\.apple\.pkg\.update\.security", string:packages);

    report = '\n  Installed security updates : ';
    if (security_boms) report += str_replace(find:'\n', replace:'\n                               ', string:security_boms);
    else report += 'n/a';
    report += '\n';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
