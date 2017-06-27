#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86654);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2012-6151",
    "CVE-2014-3565",
    "CVE-2015-0235",
    "CVE-2015-0273",
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
    "CVE-2015-5943",
    "CVE-2015-5944",
    "CVE-2015-5945",
    "CVE-2015-6563",
    "CVE-2015-6834",
    "CVE-2015-6835",
    "CVE-2015-6836",
    "CVE-2015-6837",
    "CVE-2015-6838",
    "CVE-2015-6974",
    "CVE-2015-6975",
    "CVE-2015-6976",
    "CVE-2015-6977",
    "CVE-2015-6978",
    "CVE-2015-6980",
    "CVE-2015-6983",
    "CVE-2015-6984",
    "CVE-2015-6985",
    "CVE-2015-6987",
    "CVE-2015-6988",
    "CVE-2015-6989",
    "CVE-2015-6990",
    "CVE-2015-6991",
    "CVE-2015-6992",
    "CVE-2015-6993",
    "CVE-2015-6994",
    "CVE-2015-6995",
    "CVE-2015-6996",
    "CVE-2015-7003",
    "CVE-2015-7006",
    "CVE-2015-7007",
    "CVE-2015-7008",
    "CVE-2015-7009",
    "CVE-2015-7010",
    "CVE-2015-7015",
    "CVE-2015-7016",
    "CVE-2015-7017",
    "CVE-2015-7018",
    "CVE-2015-7019",
    "CVE-2015-7020",
    "CVE-2015-7021",
    "CVE-2015-7023",
    "CVE-2015-7024",
    "CVE-2015-7035"
  );
  script_bugtraq_id(
    64048,
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
    77263,
    77265,
    77266,
    77270
  );
  script_osvdb_id(
    101547,
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
    129268,
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
    129290,
    132705,
    132706
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-10-21-4");

  script_name(english:"Mac OS X < 10.11.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.9.5 or
later but prior to 10.11.1 It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Accelerate Framework (CVE-2015-5940)

  - apache_mod_php (CVE-2015-0235, CVE-2015-0273,
    CVE-2015-6834, CVE-2015-6835, CVE-2015-6836,
    CVE-2015-6837, CVE-2015-6838)

  - ATS (CVE-2015-6985)

  - Audio (CVE-2015-5933, CVE-2015-5934, CVE-2015-7003)

  - Bom (CVE-2015-7006)

  - CFNetwork (CVE-2015-7023)

  - configd (CVE-2015-7015)

  - CoreGraphics (CVE-2015-5925, CVE-2015-5926)

  - CoreText (CVE-2015-5944, CVE-2015-6975, CVE-2015-6992,
    CVE-2015-7017)

  - Directory Utility (CVE-2015-6980)

  - Disk Images (CVE-2015-6995)

  - EFI (CVE-2015-7035)

  - File Bookmark (CVE-2015-6987)

  - FontParser (CVE-2015-5927, CVE-2015-5942, CVE-2015-6976,
    CVE-2015-6977, CVE-2015-6978, CVE-2015-6990,
    CVE-2015-6991, CVE-2015-6993, CVE-2015-7008,
    CVE-2015-7009, CVE-2015-7010, CVE-2015-7018)

  - Grand Central Dispatch (CVE-2015-6989)

  - Graphics Drivers (CVE-2015-7019, CVE-2015-7020,
    CVE-2015-7021)

  - ImageIO (CVE-2015-5935, CVE-2015-5936, CVE-2015-5937,
    CVE-2015-5938, CVE-2015-5939)

  - IOAcceleratorFamily (CVE-2015-6996)

  - IOHIDFamily (CVE-2015-6974)

  - Kernel (CVE-2015-5932, CVE-2015-6988, CVE-2015-6994)

  - libarchive (CVE-2015-6984)

  - MCX Application Restrictions (CVE-2015-7016)

  - Net-SNMP (CVE-2014-3565, CVE-2012-6151)

  - OpenGL (CVE-2015-5924)

  - OpenSSH (CVE-2015-6563)

  - Sandbox (CVE-2015-5945)

  - Script Editor (CVE-2015-7007)

  - Security (CVE-2015-6983, CVE-2015-7024)

  - SecurityAgent (CVE-2015-5943)

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205375");
  # http://prod.lists.apple.com/archives/security-announce/2015/Oct/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?309ab2ca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.11.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari User-Assisted Applescript Exec Attack');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

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
  if (c <= 70) exit(1, "Cannot determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];

if (
  version !~ "^10\.11([^0-9]|$)"
) audit(AUDIT_OS_NOT, "Mac OS X 10.11 or later", "Mac OS X "+version);

fixed_version = "10.11.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
    {
      report = '\n  Installed version : ' + version +
               '\n  Fixed version     : ' + fixed_version +
               '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
}
else exit(0, "The host is not affected since it is running Mac OS X "+version+".");
