#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93685);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/26 14:06:54 $");

  script_cve_id(
    "CVE-2016-0755",
    "CVE-2016-4617",
    "CVE-2016-4658",
    "CVE-2016-4682",
    "CVE-2016-4694",
    "CVE-2016-4696",
    "CVE-2016-4697",
    "CVE-2016-4698",
    "CVE-2016-4699",
    "CVE-2016-4700",
    "CVE-2016-4701",
    "CVE-2016-4702",
    "CVE-2016-4703",
    "CVE-2016-4706",
    "CVE-2016-4707",
    "CVE-2016-4708",
    "CVE-2016-4709",
    "CVE-2016-4710",
    "CVE-2016-4711",
    "CVE-2016-4712",
    "CVE-2016-4713",
    "CVE-2016-4715",
    "CVE-2016-4716",
    "CVE-2016-4717",
    "CVE-2016-4718",
    "CVE-2016-4722",
    "CVE-2016-4723",
    "CVE-2016-4724",
    "CVE-2016-4725",
    "CVE-2016-4726",
    "CVE-2016-4727",
    "CVE-2016-4736",
    "CVE-2016-4738",
    "CVE-2016-4739",
    "CVE-2016-4742",
    "CVE-2016-4745",
    "CVE-2016-4748",
    "CVE-2016-4750",
    "CVE-2016-4752",
    "CVE-2016-4753",
    "CVE-2016-4755",
    "CVE-2016-4771",
    "CVE-2016-4772",
    "CVE-2016-4773",
    "CVE-2016-4774",
    "CVE-2016-4775",
    "CVE-2016-4776",
    "CVE-2016-4777",
    "CVE-2016-4778",
    "CVE-2016-4779",
    "CVE-2016-5131",
    "CVE-2016-5768",
    "CVE-2016-5769",
    "CVE-2016-5770",
    "CVE-2016-5771",
    "CVE-2016-5772",
    "CVE-2016-5773",
    "CVE-2016-6174",
    "CVE-2016-6288",
    "CVE-2016-6289",
    "CVE-2016-6290",
    "CVE-2016-6291",
    "CVE-2016-6292",
    "CVE-2016-6294",
    "CVE-2016-6295",
    "CVE-2016-6296",
    "CVE-2016-6297",
    "CVE-2016-7582"
  );
  script_bugtraq_id(
    82307,
    91396,
    91397,
    91398,
    91399,
    91401,
    91403,
    91732,
    92053,
    92073,
    92074,
    92078,
    92094,
    92095,
    92097,
    92099,
    92111,
    92115,
    93054,
    93055,
    93056,
    93059,
    93060,
    93063,
    93852,
    94435
  );
  script_osvdb_id(
    144548,
    144549,
    144550,
    144551,
    144552,
    144553,
    144554,
    144555,
    144556,
    144557,
    144558,
    144559,
    144560,
    144561,
    144562,
    144563,
    144564,
    144565,
    144566,
    144567,
    144568,
    144569,
    144570,
    144571,
    144572,
    144573,
    144574,
    144575,
    144576,
    144577,
    144578,
    144579,
    144580,
    144581,
    144582,
    144583,
    144584,
    144585,
    144586,
    144587,
    144588,
    144589,
    144590,
    144591,
    144592,
    144593,
    144594,
    144595,
    146221,
    147620
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-09-20");

  script_name(english:"macOS < 10.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is prior to
10.10.5, 10.11.x prior to 10.11.6, or is not macOS 10.12. It is,
therefore, affected by multiple vulnerabilities in the following
components :

  - apache
  - apache_mod_php
  - Apple HSSPI Support
  - AppleEFIRuntime
  - AppleMobileFileIntegrity
  - AppleUCC
  - Application Firewall
  - ATS
  - Audio
  - Bluetooth
  - cd9660
  - CFNetwork
  - CommonCrypto
  - CoreCrypto
  - CoreDisplay
  - curl
  - Date & Time Pref Pane
  - DiskArbitration
  - File Bookmark
  - FontParser
  - IDS - Connectivity
  - ImageIO
  - Intel Graphics Driver
  - IOAcceleratorFamily
  - IOThunderboltFamily
  - Kerberos v5 PAM module
  - Kernel
  - libarchive
  - libxml2
  - libxpc
  - libxslt
  - mDNSResponder
  - NSSecureTextField
  - Perl
  - S2 Camera
  - Security
  - Terminal
  - WindowServer

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207170");
  # https://lists.apple.com/archives/security-announce/2016/Sep/msg00006.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c49c769b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"IPS Community Suite RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];
fixed_version = "10.12";

# Patches exist for OS X Yosemite v10.10.5 and OS X El Capitan v10.11.6
# https://support.apple.com/en-us/HT207275
# Do NOT mark them as vuln
if (
  # No 10.x patch below 10.10.5
  ver_compare(ver:version, fix:'10.10.5', strict:FALSE) == -1
  ||
  # No 10.11.x patch below 10.11.6
  (
    version =~"^10\.11($|[^0-9])"
    &&
    ver_compare(ver:version, fix:'10.11.6', strict:FALSE) == -1
  )
)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
