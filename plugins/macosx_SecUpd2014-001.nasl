#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72688);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-4073",
    "CVE-2013-4113",
    "CVE-2013-4248",
    "CVE-2013-5139",
    "CVE-2013-5178",
    "CVE-2013-5179",
    "CVE-2013-5986",
    "CVE-2013-5987",
    "CVE-2013-6420",
    "CVE-2013-6629",
    "CVE-2014-1245",
    "CVE-2014-1246",
    "CVE-2014-1247",
    "CVE-2014-1248",
    "CVE-2014-1249",
    "CVE-2014-1250",
    "CVE-2014-1252",
    "CVE-2014-1254",
    "CVE-2014-1256",
    "CVE-2014-1257",
    "CVE-2014-1258",
    "CVE-2014-1259",
    "CVE-2014-1260",
    "CVE-2014-1265"
  );
  script_bugtraq_id(
    49778,
    59826,
    60843,
    61128,
    61129,
    62536,
    63311,
    63343,
    63676,
    64225,
    64525,
    65113,
    65208,
    65777
  );
  script_osvdb_id(
    74829,
    93366,
    94628,
    95152,
    95498,
    96298,
    97435,
    98858,
    98873,
    99711,
    100517,
    100979,
    102387,
    102460,
    103742,
    103743,
    103744,
    103745,
    103746,
    103747,
    103749,
    103752,
    103753,
    103754,
    103757,
    103758,
    103760
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-02-25-1");
  script_xref(name:"IAVB", value:"2014-B-0011");
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2014-001) (BEAST)");
  script_summary(english:"Check for the presence of Security Update 2014-001.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.7 or 10.8 that
does not have Security Update 2014-001 applied. This update contains
several security-related fixes for the following components :

  - Apache
  - App Sandbox
  - ATS
  - Certificate Trust Policy
  - CFNetwork Cookies
  - CoreAnimation
  - Date and Time
  - File Bookmark
  - ImageIO
  - IOSerialFamily
  - LaunchServices
  - NVIDIA Drivers
  - PHP
  - QuickLook
  - QuickTime
  - Secure Transport

Note that successful exploitation of the most serious issues could
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT202932");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2014/Feb/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531263/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2014-001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

patch = '2014-001';

# Compare 2 patch numbers to determine if patch requirements are satisfied.
# Return true if this patch or a later patch is applied
# Return false otherwise
function check_patch(year, number)
{
  local_var p_split = split(patch, sep:'-');
  local_var p_year  = int( p_split[0]);
  local_var p_num   = int( p_split[1]);

  if (year >  p_year) return TRUE;
  else if (year <  p_year) return FALSE;
  else if (number >=  p_num) return TRUE;
  else return FALSE;
}

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");
else if ("Mac OS X 10.7" >< os && !ereg(pattern:"Mac OS X 10\.7($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Lion later than 10.7.5.");
else if ("Mac OS X 10.8" >< os && !ereg(pattern:"Mac OS X 10\.8($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Lion later than 10.8.5.");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = egrep(pattern:"^com\.apple\.pkg\.update\.security\..*bom$", string:packages);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  match = eregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(match[1]) || empty_or_null(match[2]))
    continue;

  patch_found = check_patch(year:int(match[1]), number:int(match[2]));
  if (patch_found) exit(0, "The host has Security Update " + patch + " or later installed and is therefore not affected.");
}

set_kb_item(name:'www/0/XSS', value:TRUE);

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
