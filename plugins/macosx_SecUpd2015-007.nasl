#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86829);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2015-0235",
    "CVE-2015-0273",
    "CVE-2015-4860",
    "CVE-2015-5924",
    "CVE-2015-5925",
    "CVE-2015-5926",
    "CVE-2015-5927",
    "CVE-2015-5932",
    "CVE-2015-5933",
    "CVE-2015-5934",
    "CVE-2015-5935",
    "CVE-2015-5936",
    "CVE-2015-5937",
    "CVE-2015-5938",
    "CVE-2015-5939",
    "CVE-2015-5940",
    "CVE-2015-5942",
    "CVE-2015-5944",
    "CVE-2015-6834",
    "CVE-2015-6835",
    "CVE-2015-6836",
    "CVE-2015-6837",
    "CVE-2015-6838",
    "CVE-2015-6975",
    "CVE-2015-6976",
    "CVE-2015-6977",
    "CVE-2015-6978",
    "CVE-2015-6984",
    "CVE-2015-6985",
    "CVE-2015-6989",
    "CVE-2015-6991",
    "CVE-2015-6992",
    "CVE-2015-6993",
    "CVE-2015-6996",
    "CVE-2015-7009",
    "CVE-2015-7010",
    "CVE-2015-7016",
    "CVE-2015-7018",
    "CVE-2015-7023",
    "CVE-2015-7035"
  );
  script_bugtraq_id(
    69477,
    72325,
    72701,
    74971,
    76317,
    76644,
    76649,
    76733,
    76734,
    76738,
    77162,
    77263,
    77265,
    77266,
    77270
  );
  script_osvdb_id(
    110884,
    117579,
    118589,
    126030,
    126951,
    126952,
    126953,
    126954,
    126962,
    126989,
    129123,
    129224,
    129232,
    129233,
    129234,
    129235,
    129236,
    129237,
    129238,
    129239,
    129240,
    129241,
    129242,
    129243,
    129244,
    129245,
    129246,
    129247,
    129248,
    129249,
    129250,
    129251,
    129252,
    129253,
    129254,
    129255,
    129256,
    129257,
    129258,
    129259,
    129260,
    129264,
    129265,
    129267,
    129275,
    129276,
    129277,
    129278,
    129279,
    129280,
    129281,
    129282,
    129283,
    129284,
    129285,
    129286,
    129287,
    129288,
    129289,
    129290
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-10-21-4");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Updates 2015-004 / 2015-007)");
  script_summary(english:"Checks for the presence of Security Update 2015-004 and 2015-007.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.9.5 or 10.10.5
that is missing Security Update 2015-004 or 2015-007. It is,
therefore, affected by multiple vulnerabilities in the following
components :

  - Accelerate Framework
  - apache_mod_php
  - ATS
  - Audio
  - CFNetwork
  - CoreGraphics
  - CoreText
  - EFI
  - FontParser
  - Grand Central Dispatch
  - ImageIO
  - IOAcceleratorFamily
  - Kernel
  - libarchive
  - MCX Application Restrictions
  - OpenGL

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205375");
  # https://lists.apple.com/archives/security-announce/2015/Oct/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7e01da3");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2015-004 / 2015-007 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

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

# Advisory states that update 2015-004 is available for 10.10.5 and update 2015-007 is available for 10.9.5
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.(9|10)\.5([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9.5 or Mac OS X 10.10.5");

if ("10.9.5" >< os) patch = "2015-007";
else if ("10.10.5" >< os) patch = "2015-004";

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
