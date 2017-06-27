#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69877);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

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
    "CVE-2013-1025",
    "CVE-2013-1026",
    "CVE-2013-1027",
    "CVE-2013-1028",
    "CVE-2013-1029",
    "CVE-2013-1030",
    "CVE-2013-1031",
    "CVE-2013-1032",
    "CVE-2013-1033",
    "CVE-2013-1635",
    "CVE-2013-1643",
    "CVE-2013-1775",
    "CVE-2013-1824",
    "CVE-2013-1899",
    "CVE-2013-1900",
    "CVE-2013-1901",
    "CVE-2013-1902",
    "CVE-2013-1903",
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
    60268,
    60411,
    62368,
    62369,
    62370,
    62371,
    62373,
    62374,
    62375,
    62377,
    62378,
    62381,
    62382
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
    94063,
    97281,
    97282,
    97283,
    97284,
    97285,
    97286,
    97287,
    97288,
    97289
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-09-12-1");

  script_name(english:"Mac OS X 10.8.x < 10.8.5 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.8.x that is prior
to 10.8.5. The newer version contains multiple security-related fixes
for the following components :

  - Apache
  - Bind
  - Certificate Trust Policy
  - CoreGraphics
  - ImageIO
  - Installer
  - IPSec
  - Kernel
  - Mobile Device Management
  - OpenSSL
  - PHP
  - PostgreSQL
  - Power Management
  - QuickTime
  - Screen Lock
  - sudo

This update also addresses an issue in which certain Unicode strings
could cause applications to unexpectedly quit.

Note that successful exploitation of the most serious issues could
result in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5880");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Sep/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528594/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.8.5 or later.");
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

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


if (ereg(pattern:"Mac OS X 10\.8($|\.[0-4]([^0-9]|$))", string:os))
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  security_hole(0);
}
else exit(0, "The host is not affected as it is running "+os+".");
