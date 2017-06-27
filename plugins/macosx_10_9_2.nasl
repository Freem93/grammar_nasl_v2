#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72687);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-4073",
    "CVE-2013-4113",
    "CVE-2013-4248",
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
    "CVE-2014-1255",
    "CVE-2014-1256",
    "CVE-2014-1258",
    "CVE-2014-1259",
    "CVE-2014-1261",
    "CVE-2014-1262",
    "CVE-2014-1263",
    "CVE-2014-1264",
    "CVE-2014-1265",
    "CVE-2014-1266"
  );
  script_bugtraq_id(
    59826,
    60843,
    61128,
    61129,
    61776,
    63676,
    64225,
    64525,
    65113,
    65208,
    65738,
    65777
  );
  script_osvdb_id(
    93366,
    94628,
    95152,
    95498,
    96298,
    99711,
    100517,
    100979,
    102387,
    102460,
    103583,
    103742,
    103743,
    103744,
    103745,
    103746,
    103747,
    103749,
    103750,
    103751,
    103752,
    103754,
    103755,
    103757,
    103758,
    103759,
    104973
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-02-25-1");
  script_xref(name:"IAVB", value:"2014-B-0011");

  script_name(english:"Mac OS X 10.9.x < 10.9.2 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a certificate
validation weakness.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.9.x that is prior
to 10.9.2. This update contains several security-related fixes for the
following components :

  - Apache
  - ATS
  - Certificate Trust Policy
  - CoreAnimation
  - CoreText
  - curl
  - Data Security
  - Date and Time
  - File Bookmark
  - Finder
  - ImageIO
  - NVIDIA Drivers
  - PHP
  - QuickLook
  - QuickTime

Note that successful exploitation of the most serious issues could
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6150");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2014/Feb/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531263/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9])+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];
if (!ereg(pattern:"^10\.9([^0-9]|$)", string:version)) audit(AUDIT_OS_NOT, "Mac OS X 10.9", "Mac OS X "+version);

fixed_version = "10.9.2";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

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
else exit(0, "The host is not affected as it is running Mac OS X "+version+".");
