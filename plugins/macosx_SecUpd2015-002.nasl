#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81730);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2014-4496",
    "CVE-2015-1061",
    "CVE-2015-1065",
    "CVE-2015-1066",
    "CVE-2015-1067"
  );
  script_bugtraq_id(
    72334,
    73001,
    73007
  );
  script_osvdb_id(
    117638,
    119281,
    119322,
    119323,
    119329
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-03-09-3");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2015-002)");
  script_summary(english:"Checks for the presence of Security Update 2015-002.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.8, 10.9, or 10.10
that does not have Security Update 2015-002 applied. This update
contains several security-related fixes for the following components :

  - iCloud Keychain
  - IOAcceleratorFamily
  - IOSurface
  - mach_port_kobject kernel interface
  - Secure Transport

Note that successful exploitation of the most serious of these issues
can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204413");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534827");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2015-002 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

patch = "2015-002";

# Compare 2 patch numbers to determine if patch requirements are satisfied.
# Return true if this patch or a later patch is applied
# Return false otherwise
function check_patch(year, number)
{
  local_var p_split = split(patch, sep:"-");
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
if (!ereg(pattern:"Mac OS X 10\.([89]|10)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8 / 10.9 / 10.10");
else if ("Mac OS X 10.8" >< os && !ereg(pattern:"Mac OS X 10\.8($|\.[0-5]([^0-9]|$))", string:os))
  exit(0, "The remote host uses a version of Mac OS X Mountain Lion later than 10.8.5.");
else if ("Mac OS X 10.9" >< os && !ereg(pattern:"Mac OS X 10\.9($|\.[0-5]([^0-9]|$))", string:os))
  exit(0, "The remote host uses a version of Mac OS X Mavericks later than 10.9.5.");
else if ("Mac OS X 10.10" >< os && !ereg(pattern:"Mac OS X 10\.10($|\.[0-2]([^0-9]|$))", string:os))
  exit(0, "The remote host uses a version of Mac OS X Yosemite later than 10.10.2.");

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

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
