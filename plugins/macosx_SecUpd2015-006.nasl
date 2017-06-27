#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85409);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2012-6685",
    "CVE-2014-0067",
    "CVE-2014-0191",
    "CVE-2014-3581",
    "CVE-2014-3583",
    "CVE-2014-3660",
    "CVE-2014-8109",
    "CVE-2014-8161",
    "CVE-2015-0228",
    "CVE-2015-0241",
    "CVE-2015-0242",
    "CVE-2015-0243",
    "CVE-2015-0244",
    "CVE-2015-0253",
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-2783",
    "CVE-2015-2787",
    "CVE-2015-3183",
    "CVE-2015-3185",
    "CVE-2015-3307",
    "CVE-2015-3329",
    "CVE-2015-3330",
    "CVE-2015-3729",
    "CVE-2015-3730",
    "CVE-2015-3731",
    "CVE-2015-3732",
    "CVE-2015-3733",
    "CVE-2015-3734",
    "CVE-2015-3735",
    "CVE-2015-3736",
    "CVE-2015-3737",
    "CVE-2015-3738",
    "CVE-2015-3739",
    "CVE-2015-3740",
    "CVE-2015-3741",
    "CVE-2015-3742",
    "CVE-2015-3743",
    "CVE-2015-3744",
    "CVE-2015-3745",
    "CVE-2015-3746",
    "CVE-2015-3747",
    "CVE-2015-3748",
    "CVE-2015-3749",
    "CVE-2015-3750",
    "CVE-2015-3751",
    "CVE-2015-3752",
    "CVE-2015-3753",
    "CVE-2015-3754",
    "CVE-2015-3755",
    "CVE-2015-3765",
    "CVE-2015-3779",
    "CVE-2015-3783",
    "CVE-2015-3788",
    "CVE-2015-3789",
    "CVE-2015-3790",
    "CVE-2015-3791",
    "CVE-2015-3792",
    "CVE-2015-3804",
    "CVE-2015-3807",
    "CVE-2015-4021",
    "CVE-2015-4022",
    "CVE-2015-4024",
    "CVE-2015-4025",
    "CVE-2015-4026",
    "CVE-2015-4147",
    "CVE-2015-4148",
    "CVE-2015-5751",
    "CVE-2015-5753",
    "CVE-2015-5756",
    "CVE-2015-5761",
    "CVE-2015-5771",
    "CVE-2015-5773",
    "CVE-2015-5775",
    "CVE-2015-5776",
    "CVE-2015-5779"
  );
  script_bugtraq_id(
    65721,
    67233,
    70644,
    71656,
    71657,
    72538,
    72540,
    72542,
    72543,
    73040,
    73041,
    73357,
    73431,
    74174,
    74204,
    74239,
    74240,
    74700,
    74703,
    74902,
    74903,
    74904,
    75056,
    75103,
    75154,
    75156,
    75157,
    75158,
    75161,
    75963,
    75964,
    75965,
    76338,
    76339,
    76340,
    76341,
    76342,
    76343,
    76344
  );
  script_osvdb_id(
    90946,
    103550,
    106710,
    112168,
    113389,
    114570,
    115375,
    118033,
    118034,
    118035,
    118036,
    118037,
    118038,
    119066,
    119774,
    119904,
    120925,
    120930,
    120938,
    122125,
    122126,
    122127,
    122257,
    122261,
    122268,
    126104,
    126105,
    126106,
    126107,
    126108,
    126109,
    126110,
    126111,
    126112,
    126113,
    126114,
    126115,
    126116,
    126117,
    126118,
    126119,
    126120,
    126121,
    126122,
    126123,
    126124,
    126125,
    126126,
    126127,
    126128,
    126129,
    126130,
    126190,
    126199,
    126206,
    126207,
    126208,
    126233,
    126235,
    126239,
    126241,
    126243,
    126244,
    126245,
    126246,
    126247,
    126248,
    126249,
    126250,
    126251,
    126253
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-08-13-2");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2015-006)");
  script_summary(english:"Checks for the presence of Security Update 2015-006.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.8.5 or 10.9.5
that is missing Security Update 2015-006. It is, therefore, affected
by multiple vulnerabilities in the following components :

  - apache
  - apache_mod_php
  - CoreText
  - FontParser
  - Libinfo
  - libxml2
  - OpenSSL
  - perl
  - PostgreSQL
  - QL Office
  - Quartz Composer Framework
  - QuickTime 7
  - SceneKit

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205031");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2015-006 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

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

patch = "2015-006";

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

# Advisory states that the update is available for 10.10.2
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[89]\.5([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8.5 or Mac OS X 10.9.5");

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
