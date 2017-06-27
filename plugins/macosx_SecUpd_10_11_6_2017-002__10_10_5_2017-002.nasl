#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100271);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/18 13:50:47 $");

  script_cve_id(
    "CVE-2017-2512",
    "CVE-2017-2516",
    "CVE-2017-2524",
    "CVE-2017-2527",
    "CVE-2017-2533",
    "CVE-2017-2535",
    "CVE-2017-2537",
    "CVE-2017-2540",
    "CVE-2017-2541",
    "CVE-2017-2546",
    "CVE-2017-2548",
    "CVE-2017-6979",
    "CVE-2017-6990"
  );
  script_bugtraq_id(
    98483
  );
  script_osvdb_id(
    157550,
    157553,
    157556,
    157557,
    157558,
    157567,
    157568,
    157570,
    157571,
    157574,
    157583,
    157597,
    157606
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-05-15-1");
  script_xref(name:"IAVA", value:"2017-A-0150");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2017-002)");
  script_summary(english:"Checks for the presence of Security Update 2017-002.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.10.5 or 10.11.6
that is missing a security update. It is therefore, affected by
multiple vulnerabilities :

  - A memory corruption issue exists in the Sandbox
    component that allows an unauthenticated, remote
    attacker to escape an application sandbox.
    (CVE-2017-2512)

  - An information disclosure vulnerability exists in the
    Kernel component due to improper sanitization of
    user-supplied input. A local attacker can exploit this
    to read the contents of restricted memory.
    (CVE-2017-2516)

  - An unspecified memory corruption issue exists in the
    TextInput component when parsing specially crafted data.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-2524)

  - A flaw exists in the CoreAnimation component when
    handling specially crafted data. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2017-2527)

  - A race condition exists in the DiskArbitration feature
    that allow a local attacker to gain system-level
    privileges. (CVE-2017-2533)

  - A resource exhaustion issue exists in the Security
    component due to improper validation of user-supplied
    input. A local attacker can exploit this to exhaust
    resources and escape an application sandbox.
    (CVE-2017-2535)

  - Multiple memory corruption issues exist in the
    WindowServer component that allow a local attacker to
    execute arbitrary code with system-level privileges.
    (CVE-2017-2537, CVE-2017-2548)

  - An information disclosure vulnerability exists in
    WindowServer component in the _XGetConnectionPSN()
    function due to improper validation of user-supplied
    input. A local attacker can exploit this to read the
    contents of restricted memory. (CVE-2017-2540)

  - A stack-based buffer overflow condition exists in the
    WindowServer component in the _XGetWindowMovementGroup()
    function due to improper validation of user-supplied
    input. A local attacker can exploit this to execute
    arbitrary code with the privileges of WindowServer.
    (CVE-2017-2541)

  - A memory corruption issue exists in the Kernel component
    that allow a local attacker to gain kernel-level
    privileges. (CVE-2017-2546)

  - A race condition exists in the IOSurface component that
    allows a local attacker to execute arbitrary code with
    kernel-level privileges. (CVE-2017-6979)

  - An information disclosure vulnerability exists in HFS
    component due to improper sanitization of user-supplied
    input. A local attacker can exploit this to read the
    contents of restricted memory. (CVE-2017-6990)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207797");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2017/May/47");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2017-002 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

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

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item_or_exit("Host/MacOSX/Version");

if (!preg(pattern:"Mac OS X 10\.(10\.5|11\.6)([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.10.5 or Mac OS X 10.11.6");

if ("10.10.5" >< os || "10.11.6" >< os) patch = "2017-002";

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = pgrep(
  pattern:"^com\.apple\.pkg\.update\.(security\.|os\.SecUpd).*bom$",
  string:packages
);
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
