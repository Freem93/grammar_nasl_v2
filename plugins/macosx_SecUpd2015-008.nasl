#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87321);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2011-2895",
    "CVE-2012-0876",
    "CVE-2012-1147",
    "CVE-2012-1148",
    "CVE-2015-3807",
    "CVE-2015-5333",
    "CVE-2015-5334",
    "CVE-2015-6908",
    "CVE-2015-7001",
    "CVE-2015-7038",
    "CVE-2015-7039",
    "CVE-2015-7040",
    "CVE-2015-7041",
    "CVE-2015-7042",
    "CVE-2015-7043",
    "CVE-2015-7044",
    "CVE-2015-7045",
    "CVE-2015-7046",
    "CVE-2015-7047",
    "CVE-2015-7052",
    "CVE-2015-7053",
    "CVE-2015-7054",
    "CVE-2015-7058",
    "CVE-2015-7059",
    "CVE-2015-7060",
    "CVE-2015-7061",
    "CVE-2015-7062",
    "CVE-2015-7063",
    "CVE-2015-7064",
    "CVE-2015-7065",
    "CVE-2015-7066",
    "CVE-2015-7067",
    "CVE-2015-7068",
    "CVE-2015-7071",
    "CVE-2015-7073",
    "CVE-2015-7074",
    "CVE-2015-7075",
    "CVE-2015-7076",
    "CVE-2015-7077",
    "CVE-2015-7078",
    "CVE-2015-7081",
    "CVE-2015-7083",
    "CVE-2015-7084",
    "CVE-2015-7094",
    "CVE-2015-7105",
    "CVE-2015-7106",
    "CVE-2015-7107",
    "CVE-2015-7108",
    "CVE-2015-7109",
    "CVE-2015-7110",
    "CVE-2015-7111",
    "CVE-2015-7112",
    "CVE-2015-7803",
    "CVE-2015-7804"
  );
  script_bugtraq_id(
    49124,
    52379,
    76343,
    76714,
    76959,
    77112,
    78719,
    78721,
    78725,
    78730,
    78733,
    78735
  );
  script_osvdb_id(
    74927,
    80892,
    80893,
    80894,
    126235,
    127342,
    128347,
    128348,
    128984,
    128985,
    131381,
    131382,
    131386,
    131387,
    131388,
    131389,
    131390,
    131391,
    131392,
    131393,
    131394,
    131395,
    131396,
    131397,
    131398,
    131400,
    131401,
    131402,
    131403,
    131404,
    131411,
    131413,
    131414,
    131415,
    131416,
    131417,
    131418,
    131419,
    131420,
    131421,
    131422,
    131423,
    131424,
    131425,
    131426,
    131427,
    131428,
    131430,
    131431,
    131432,
    131433,
    131434,
    131437,
    131438
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-12-08-3");
  script_xref(name:"EDB-ID", value:"38145");
  script_xref(name:"EDB-ID", value:"38917");
  script_xref(name:"EDB-ID", value:"39357");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Updates 2015-005 / 2015-008)");
  script_summary(english:"Checks for the presence of Security Update 2015-005 and 2015-008.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.9.5 or 10.10.5
that is missing Security Update 2015-005 or 2015-008. It is,
therefore, affected by multiple vulnerabilities in the following
components :

  - apache_mod_php
  - AppSandbox
  - Bluetooth
  - CFNetwork HTTPProtocol
  - Compression
  - Configuration Profiles
  - CoreGraphics
  - CoreMedia Playback
  - Disk Images
  - EFI
  - File Bookmark
  - Hypervisor
  - iBooks
  - ImageIO
  - Intel Graphics Driver
  - IOAcceleratorFamily
  - IOHIDFamily
  - IOKit SCSI
  - IOThunderboltFamily
  - Kernel
  - kext tools
  - Keychain Access
  - libarchive
  - libc
  - libexpat
  - libxml2
  - OpenGL
  - OpenLDAP
  - OpenSSH
  - QuickLook
  - Sandbox
  - Security
  - System Integrity Protection

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205637");
  # https://lists.apple.com/archives/security-announce/2015/Dec/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec39a4a4");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2015-006 (OS X 10.9.5) / 2015-008 (OS X
10.10.5) or later. Note that Security Update 2015-006 is a
replacement for the earlier 2015-005 update mentioned in the original
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");

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

# Advisory states that update 2015-005 is available for 10.10.5 and update 2015-008 is available for 10.9.5
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.(9|10)\.5([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9.5 or Mac OS X 10.10.5");

if ( "10.9.5" >< os) patch = "2015-008";
else if ( "10.10.5" >< os ) patch = "2015-005";

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
