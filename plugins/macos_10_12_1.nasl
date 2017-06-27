#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94253);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/26 14:06:54 $");

  script_cve_id(
    "CVE-2016-4660",
    "CVE-2016-4661",
    "CVE-2016-4667",
    "CVE-2016-4669",
    "CVE-2016-4670",
    "CVE-2016-4673",
    "CVE-2016-4674",
    "CVE-2016-4675",
    "CVE-2016-4678",
    "CVE-2016-4679",
    "CVE-2016-4688",
    "CVE-2016-4721",
    "CVE-2016-4780",
    "CVE-2016-7577",
    "CVE-2016-7579",
    "CVE-2016-7584",
    "CVE-2016-7613"
  );
  script_bugtraq_id(
    93849,
    93852,
    93856,
    94116,
    94429,
    94433,
    94571,
    94572,
    96332
  );
  script_osvdb_id(
    146204,
    146206,
    146207,
    146209,
    146210,
    146213,
    146217,
    146218,
    146219,
    146222,
    146253,
    146343,
    147610,
    147611,
    147944,
    147945,
    152296
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-10-24-2");

  script_name(english:"macOS 10.12.x < 10.12.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.12.x
prior to macOS 10.12.1. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - ATS
  - AppleMobileFileIntegrity
  - AppleSMC
  - CFNetwork Proxies
  - CoreGraphics
  - FaceTime
  - FontParser
  - IDS - Connectivity
  - Kernel
  - libarchive
  - libxpc
  - ntfs
  - Security
  - Thunderbolt

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207275");
  # http://lists.apple.com/archives/security-announce/2016/Oct/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9a074e5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.12.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/25");

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

matches = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];
if (version !~ "^10\.12($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);

fixed_version = "10.12.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
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
