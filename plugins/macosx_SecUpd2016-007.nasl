#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95918);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/20 14:45:31 $");

  script_cve_id(
    "CVE-2016-6304",
    "CVE-2016-7596", 
    "CVE-2016-7604"
  );
  script_bugtraq_id(
    93150,
    94903
  );
  script_osvdb_id(
    144688,
    148751,
    148754
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-12-13-1");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Updates 2016-003 / 2016-007)");
  script_summary(english:"Checks for the presence of Security Update 2016-003 and 2016-007.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.10.5 or 10.11.6
that is missing a security update. It is therefore, affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists in the
    ssl_parse_clienthello_tlsext() function within file
    ssl/t1_lib.c when handling oversize OCSP Status Request
    extensions from clients. An unauthenticated, remote
    attacker can exploit this to cause memory exhaustion in
    a process linked with the library. (CVE-2016-6304)

  - A memory corruption issue exists in Bluetooth due to
    improper validation of user-supplied input. A local
    attacker can exploit this, via a specially crafted
    application, to cause a denial of service condition or
    the execution of arbitrary code with kernel level
    privileges. (CVE-2016-7596)

  - A NULL pointer dereference flaw exists in the
    CoreCapture component due to improper validation of
    user-supplied input. A local attacker can exploit this
    to cause a denial of service condition. (CVE-2016-7604)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207423");
  # http://lists.apple.com/archives/security-announce/2016/Dec/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38dabd46");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2016-007 (OS X 10.10.5) / 2016-003 (OS X
10.11.6) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.(10\.5|11\.6)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.10.5 or Mac OS X 10.11.6");

if ( "10.10.5" >< os) patch = "2016-007";
else if ( "10.11.6" >< os ) patch = "2016-003";

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = egrep(pattern:"^com\.apple\.pkg\.update\.(security\.|os\.SecUpd).*bom$", string:packages);
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
