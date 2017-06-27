#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81087);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2014-1595",
    "CVE-2014-3192",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-3568",
    "CVE-2014-4371",
    "CVE-2014-4389",
    "CVE-2014-4419",
    "CVE-2014-4420",
    "CVE-2014-4421",
    "CVE-2014-4460",
    "CVE-2014-4461",
    "CVE-2014-4476",
    "CVE-2014-4477",
    "CVE-2014-4479",
    "CVE-2014-4481",
    "CVE-2014-4483",
    "CVE-2014-4484",
    "CVE-2014-4485",
    "CVE-2014-4486",
    "CVE-2014-4487",
    "CVE-2014-4488",
    "CVE-2014-4489",
    "CVE-2014-4491",
    "CVE-2014-4492",
    "CVE-2014-4495",
    "CVE-2014-4498",
    "CVE-2014-4499",
    "CVE-2014-6277",
    "CVE-2014-7186",
    "CVE-2014-7187",
    "CVE-2014-8517",
    "CVE-2014-8817",
    "CVE-2014-8819",
    "CVE-2014-8820",
    "CVE-2014-8821",
    "CVE-2014-8822",
    "CVE-2014-8823",
    "CVE-2014-8824",
    "CVE-2014-8825",
    "CVE-2014-8826",
    "CVE-2014-8827",
    "CVE-2014-8830",
    "CVE-2014-8831",
    "CVE-2014-8832",
    "CVE-2014-8833",
    "CVE-2014-8834",
    "CVE-2014-8835",
    "CVE-2014-8836",
    "CVE-2014-8837",
    "CVE-2014-8838",
    "CVE-2014-8839"
  );
  script_bugtraq_id(
    69919,
    69924,
    69927,
    69928,
    69950,
    70152,
    70154,
    70165,
    70273,
    70574,
    70585,
    70586,
    70792,
    71135,
    71136,
    71394,
    72327,
    72328,
    72329,
    72330,
    72331,
    72341
  );
  script_osvdb_id(
    111676,
    111677,
    111678,
    111679,
    111909,
    112096,
    112097,
    112158,
    112753,
    113251,
    113374,
    113377,
    113913,
    114727,
    114729,
    115201,
    117621,
    117622,
    117623,
    117624,
    117625,
    117627,
    117628,
    117630,
    117631,
    117632,
    117633,
    117634,
    117635,
    117645,
    117647,
    117648,
    117649,
    117652,
    117654,
    117655,
    117656,
    117658,
    117659,
    117660,
    117663,
    117664,
    117665,
    117666,
    117667,
    117668
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-01-27-4");

  script_name(english:"Mac OS X 10.10.x < 10.10.2 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.10.x that is prior
to version 10.10.2. This update contains several security-related
fixes for the following components :

  - bash
  - Bluetooth
  - CFNetwork Cache
  - CommerceKit Framework
  - CoreGraphics
  - CoreSymbolication
  - CPU Software
  - FontParser
  - Foundation
  - Intel Graphics Driver
  - IOAcceleratorFamily
  - IOHIDFamily
  - IOKit
  - IOUSBFamily
  - Kernel
  - LaunchServices
  - libnetcore
  - LoginWindow
  - lukemftp
  - OpenSSL
  - Safari
  - SceneKit
  - Security
  - security_taskgate
  - Spotlight
  - SpotlightIndex
  - sysmond
  - UserAccountUpdater

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT204244");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534559");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

fixed_version = "10.10.2";
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
else exit(0, "The host is not affected as it is running Mac OS X "+version+".");
