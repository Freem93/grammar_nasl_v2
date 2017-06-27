#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84488);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0235",
    "CVE-2015-0273",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0293",
    "CVE-2015-1157",
    "CVE-2015-1798",
    "CVE-2015-1799",
    "CVE-2015-3661",
    "CVE-2015-3662",
    "CVE-2015-3663",
    "CVE-2015-3666",
    "CVE-2015-3667",
    "CVE-2015-3668",
    "CVE-2015-3671",
    "CVE-2015-3672",
    "CVE-2015-3673",
    "CVE-2015-3674",
    "CVE-2015-3675",
    "CVE-2015-3676",
    "CVE-2015-3677",
    "CVE-2015-3678",
    "CVE-2015-3679",
    "CVE-2015-3680",
    "CVE-2015-3681",
    "CVE-2015-3682",
    "CVE-2015-3683",
    "CVE-2015-3684",
    "CVE-2015-3685",
    "CVE-2015-3686",
    "CVE-2015-3687",
    "CVE-2015-3688",
    "CVE-2015-3689",
    "CVE-2015-3690",
    "CVE-2015-3691",
    "CVE-2015-3692",
    "CVE-2015-3693",
    "CVE-2015-3694",
    "CVE-2015-3695",
    "CVE-2015-3696",
    "CVE-2015-3697",
    "CVE-2015-3698",
    "CVE-2015-3699",
    "CVE-2015-3700",
    "CVE-2015-3701",
    "CVE-2015-3702",
    "CVE-2015-3703",
    "CVE-2015-3704",
    "CVE-2015-3705",
    "CVE-2015-3706",
    "CVE-2015-3707",
    "CVE-2015-3708",
    "CVE-2015-3709",
    "CVE-2015-3710",
    "CVE-2015-3711",
    "CVE-2015-3712",
    "CVE-2015-3713",
    "CVE-2015-3714",
    "CVE-2015-3715",
    "CVE-2015-3716",
    "CVE-2015-3717",
    "CVE-2015-3718",
    "CVE-2015-3719",
    "CVE-2015-3720",
    "CVE-2015-3721",
    "CVE-2015-4000",
    "CVE-2015-7036"
  );
  script_bugtraq_id(
    72325,
    72701,
    73225,
    73227,
    73231,
    73232,
    73237,
    73239,
    73950,
    73951,
    74733
  );
  script_osvdb_id(
    123920,
    123921,
    123922,
    123923,
    123924,
    123925,
    123926,
    123927,
    123928,
    123929,
    123930,
    123931,
    123932,
    123933,
    123934,
    123935,
    123936,
    123937,
    123938,
    123938,
    123940,
    123941,
    123942,
    123943,
    123944,
    123945,
    123946,
    123947,
    123948,
    123949,
    123950,
    123951,
    123952,
    123953,
    123954,
    123955,
    123956,
    123957,
    123958,
    123959,
    123960,
    123961,
    123962,
    123963,
    130436
  );
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-06-30-2");

  script_name(english:"Mac OS X 10.10.x < 10.10.4 Multiple Vulnerabilities (GHOST) (Logjam)");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.10.x that is prior
to 10.10.4. It is, therefore, affected multiple vulnerabilities in the
following components :

  - Admin Framework
  - afpserver
  - apache
  - AppleFSCompression
  - AppleGraphicsControl
  - AppleThunderboltEDMService
  - ATS
  - Bluetooth
  - Certificate Trust Policy
  - CFNetwork HTTPAuthentication
  - CoreText
  - coreTLS
  - DiskImages
  - Display Drivers
  - EFI
  - FontParser
  - Graphics Driver
  - ImageIO
  - Install Framework Legacy
  - Intel Graphics Driver
  - IOAcceleratorFamily
  - IOFireWireFamily
  - Kernel
  - kext tools
  - Mail
  - ntfs
  - ntp
  - OpenSSL
  - QuickTime
  - Security
  - Spotlight
  - SQLite
  - System Stats
  - TrueTypeScaler
  - zip

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ca/HT204942");
  # http://lists.apple.com/archives/security-announce/2015/Jun/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?956357d4");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.10.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple OS X Entitlements Rootpipe Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];
if (!ereg(pattern:"^10\.10([^0-9]|$)", string:version)) audit(AUDIT_OS_NOT, "Mac OS X 10.10", "Mac OS X "+version);

fixed_version = "10.10.4";
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
