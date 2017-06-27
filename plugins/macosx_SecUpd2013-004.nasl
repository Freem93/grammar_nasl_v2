#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69878);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2012-0883",
    "CVE-2012-2686",
    "CVE-2012-2687",
    "CVE-2012-3499",
    "CVE-2012-3817",
    "CVE-2012-4244",
    "CVE-2012-4558",
    "CVE-2012-5166",
    "CVE-2012-5688",
    "CVE-2013-0166",
    "CVE-2013-0169",
    "CVE-2013-1027",
    "CVE-2013-1028",
    "CVE-2013-1030",
    "CVE-2013-1032",
    "CVE-2013-1635",
    "CVE-2013-1643",
    "CVE-2013-1775",
    "CVE-2013-1824",
    "CVE-2013-1899",
    "CVE-2013-1900",
    "CVE-2013-1901",
    "CVE-2013-1902",
    "CVE-2013-1903",
    "CVE-2013-2020",
    "CVE-2013-2021",
    "CVE-2013-2110",
    "CVE-2013-2266"
  );
  script_bugtraq_id(
    53046,
    54658,
    55131,
    55522,
    55852,
    56817,
    57755,
    57778,
    58165,
    58203,
    58224,
    58736,
    58766,
    58876,
    58877,
    58878,
    58879,
    58882,
    59434,
    60118,
    60268,
    60411,
    62370,
    62371,
    62373,
    62375,
    62377
  );
  script_osvdb_id(
    81359,
    84228,
    84818,
    85417,
    86118,
    88126,
    89848,
    89865,
    89866,
    90556,
    90557,
    90677,
    90921,
    90922,
    91712,
    91958,
    91959,
    91960,
    91961,
    91962,
    92834,
    92835,
    94063,
    97284,
    97286,
    97288,
    97289
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-09-12-1");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2013-004)");
  script_summary(english:"Check for the presence of Security Update 2013-004");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.6 or 10.7 that
does not have Security Update 2013-004 applied.  This update contains
several security-related fixes for the following component :

  - Apache
  - Bind
  - Certificate Trust Policy
  - ClamAV
  - Installer
  - IPSec
  - Mobile Device Management
  - OpenSSL
  - PHP
  - PostgreSQL
  - QuickTime
  - sudo

Note that successful exploitation of the most serious issues could
result in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5880");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Sep/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528594/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2013-004 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
if (!ereg(pattern:"Mac OS X 10\.[67]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.6 / 10.7");
else if ("Mac OS X 10.6" >< os && !ereg(pattern:"Mac OS X 10\.6($|\.[0-8]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Snow Leopard later than 10.6.8.");
else if ("Mac OS X 10.7" >< os && !ereg(pattern:"Mac OS X 10\.7($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Lion later than 10.7.5.");


packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
if (
  egrep(pattern:"^com\.apple\.pkg\.update\.security(\.10\.[6-8]\..+)?\.(2013\.00[4-9]|201[4-9]\.[0-9]+)(\.(snowleopard[0-9.]*|lion))?\.bom", string:packages)
) exit(0, "The host has Security Update 2013-004 or later installed and is therefore not affected.");
else
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    security_boms = egrep(pattern:"^com\.apple\.pkg\.update\.security", string:packages);

    report = '\n  Installed security BOMs : ';
    if (security_boms) report += str_replace(find:'\n', replace:'\n                            ', string:security_boms);
    else report += 'n/a';
    report += '\n';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
