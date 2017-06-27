#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100427);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/26 14:06:54 $");

  script_cve_id(
    "CVE-2016-4662",
    "CVE-2016-4663",
    "CVE-2016-4669",
    "CVE-2016-4671",
    "CVE-2016-4681",
    "CVE-2016-4682",
    "CVE-2016-4683"
  );
  script_bugtraq_id(
    93849,
    93852,
    94431
  );
  script_osvdb_id(
    146213,
    146216,
    146220,
    146221,
    146223,
    146264,
    146265
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-10-24-2");

  script_name(english:"Mac OS X 10.10.5 / 10.11.6 Multiple Vulnerabilities (Security Update 2016-002 / 2016-006)");
  script_summary(english:"Checks for the presence of Security Update 2016-002 and 2016-006.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.10.5 but
is missing Security Update 2016-006, or else it is version 10.11.6 but
is missing Security Update 2016-002. It is, therefore, affected by
multiple vulnerabilities :

  - A memory corruption issue exists in the
    AppleGraphicsControl component due to improper lock
    state checking. A local attacker can exploit this, via a
    specially crafted application, to execute arbitrary code
    with kernel-level privileges. (CVE-2016-4662)

  - A memory corruption issue exists in the NVIDIA Graphics
    Driver due to improper validation of user-supplied
    input. A local attacker can exploit this to cause a
    denial of service condition. (CVE-2016-4663)

  - Multiple flaws exist in the System Boot component due to
    improper validation of user-supplied input. A local
    attacker can exploit these to terminate the system or
    execute arbitrary code with kernel-level privileges.
    (CVE-2016-4669)

  - An out-of-bounds write error exists in the ImageIO
    component when parsing PDF files due to improper bounds
    checking. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted PDF file, to execute arbitrary code.
    (CVE-2016-4671)

  - A memory corruption issue exists in the Core Image
    component when handling JPEG files due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a specially crafted JPEG file, to execute
    arbitrary code. (CVE-2016-4681)

  - An out-of-bounds read error exists in the ImageIO
    component when parsing specially crafted SGI images. An
    unauthenticated, remote attacker can exploit this to
    disclose potentially sensitive information in process
    memory. (CVE-2016-4682)

  - Multiple out-of-bounds read and write errors exist in
    the ImageIO component when parsing specially crafted
    SGI images. An unauthenticated, remote attacker can
    exploit these to disclose potentially sensitive
    information, cause a denial of service condition, or
    execute arbitrary code. (CVE-2016-4683)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207275");
  # https://lists.apple.com/archives/security-announce/2016/Oct/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34f01fa1");
 script_set_attribute(attribute:"solution", value:
"If running Mac OS X version 10.10.5, install Security Update 2016-006
or later. If running version Mac OS X version 10.11.6, install
Security Update 2016-002 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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
function check_patch(year, number, fixed_patch_string)
{
  local_var p_split = split(fixed_patch_string, sep:"-");
  local_var p_year  = int( p_split[0]);
  local_var p_num   = int( p_split[1]);

  if (year >  p_year) return TRUE;
  else if (year <  p_year) return FALSE;
  else if (number >=  p_num) return TRUE;
  else return FALSE;
}

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item_or_exit("Host/MacOSX/Version");

if (preg(pattern:"Mac OS X 10\.10\.5($|[^0-9])", string:os))
  fix_patch = "2016-006";
else if (preg(pattern:"Mac OS X 10\.11\.6($|[^0-9])", string:os))
  fix_patch = "2016-002";
else
  audit(AUDIT_OS_NOT, "Mac OS X 10.10.5 or Mac OS X 10.11.6");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = pgrep(pattern:"^com\.apple\.pkg\.update\.security\..*bom$", string:packages);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  match = pregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(match[1]) || empty_or_null(match[2]))
    continue;

  patch_found = check_patch(year:int(match[1]), number:int(match[2]), fixed_patch_string:fix_patch);
  if (patch_found) exit(0, "The host, version " + os + ", has Security Update " + fix_patch + " or later installed and is therefore not affected.");
}

report =  '\n  Operating system version : ' + os +
report += '\n  Missing security update  : ' + fix_patch;
report += '\n  Installed security BOMs  : ';
if (sec_boms_report)
  report += str_replace(
              find   :'\n',
              replace:'\n                            ',
              string :sec_boms_report
              );
else
  report += 'n/a';

report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
