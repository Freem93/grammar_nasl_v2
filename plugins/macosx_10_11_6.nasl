#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92496);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");

  script_cve_id(
    "CVE-2013-7456",
    "CVE-2014-9862",
    "CVE-2016-0718",
    "CVE-2016-1684",
    "CVE-2016-1836",
    "CVE-2016-1863",
    "CVE-2016-1864",
    "CVE-2016-1865",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2107",
    "CVE-2016-2108",
    "CVE-2016-2108",
    "CVE-2016-2109",
    "CVE-2016-2109",
    "CVE-2016-2176",
    "CVE-2016-4447",
    "CVE-2016-4448",
    "CVE-2016-4449",
    "CVE-2016-4483",
    "CVE-2016-4582",
    "CVE-2016-4594",
    "CVE-2016-4595",
    "CVE-2016-4596",
    "CVE-2016-4597",
    "CVE-2016-4598",
    "CVE-2016-4599",
    "CVE-2016-4600",
    "CVE-2016-4601",
    "CVE-2016-4602",
    "CVE-2016-4607",
    "CVE-2016-4608",
    "CVE-2016-4609",
    "CVE-2016-4610",
    "CVE-2016-4612",
    "CVE-2016-4614",
    "CVE-2016-4615",
    "CVE-2016-4616",
    "CVE-2016-4619",
    "CVE-2016-4621",
    "CVE-2016-4625",
    "CVE-2016-4626",
    "CVE-2016-4629",
    "CVE-2016-4630",
    "CVE-2016-4631",
    "CVE-2016-4632",
    "CVE-2016-4633",
    "CVE-2016-4634",
    "CVE-2016-4635",
    "CVE-2016-4637",
    "CVE-2016-4638",
    "CVE-2016-4639",
    "CVE-2016-4640",
    "CVE-2016-4641",
    "CVE-2016-4645",
    "CVE-2016-4646",
    "CVE-2016-4647",
    "CVE-2016-4648",
    "CVE-2016-4649",
    "CVE-2016-4650",
    "CVE-2016-4652",
    "CVE-2016-5093",
    "CVE-2016-5094",
    "CVE-2016-5096"
  );
  script_bugtraq_id(
    90856,
    90857,
    90859,
    90861,
    90864,
    90865,
    90876,
    90946,
    91824,
    91826,
    91828,
    91829,
    91834,
    92034
  );
  script_osvdb_id(
    138996,
    138997,
    139004,
    139005,
    141595,
    141596,
    141597,
    141598,
    141599,
    141600,
    141601,
    141602,
    141603,
    141604,
    141605,
    141606,
    141607,
    141608,
    141609,
    141610,
    141611,
    141612,
    141613,
    141614,
    141615,
    141616,
    141617,
    141618,
    141619,
    141620,
    141621,
    141622,
    141623,
    141624,
    141625,
    141626,
    141627,
    141628,
    141629,
    141630,
    141631,
    141632,
    141633,
    141634,
    141635,
    141636,
    141637,
    141703
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-07-18-1");

  script_name(english:"Mac OS X 10.11.x < 10.11.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.11.x prior
to 10.11.6. It is, therefore, affected by multiple vulnerabilities in
the following components :

  - apache_mod_php
  - Audio
  - bsdiff
  - CFNetwork
  - CoreGraphics
  - FaceTime
  - Graphics Drivers
  - ImageIO
  - Intel Graphics Driver
  - IOHIDFamily
  - IOKit
  - IOSurface
  - Kernel
  - libc++abi
  - libexpat
  - LibreSSL
  - libxml2
  - libxslt
  - Login Window
  - OpenSSL
  - QuickTime
  - Safari Login AutoFill
  - Sandbox Profiles

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT206903");
  # http://lists.apple.com/archives/security-announce/2016/Jul/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5da74f53");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.11.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]{1,2})+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];
if (!ereg(pattern:"^10\.11([^0-9]|$)", string:version)) audit(AUDIT_OS_NOT, "Mac OS X 10.11", "Mac OS X "+version);

fixed_version = "10.11.6";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
      report = '\n  Installed version : ' + version +
               '\n  Fixed version     : ' + fixed_version +
               '\n';
      security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else exit(0, "The host is not affected as it is running Mac OS X "+version+".");
