#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87314);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

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
    "CVE-2015-7115",
    "CVE-2015-7116",
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
    131438,
    132701,
    132702
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-12-08-3");
  script_xref(name:"EDB-ID", value:"38917");
  
  script_name(english:"Mac OS X 10.11.x < 10.11.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.11.x prior
to 10.11.2. It is, therefore, affected by multiple vulnerabilities in
the following components :

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
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205579");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205637");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X version 10.11.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");

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

fixed_version = "10.11.2";
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
