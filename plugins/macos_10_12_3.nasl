#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96731);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/26 14:48:47 $");

  script_cve_id(
    "CVE-2016-1248",
    "CVE-2016-8670",
    "CVE-2016-8687",
    "CVE-2016-9933",
    "CVE-2016-9934",
    "CVE-2017-2353",
    "CVE-2017-2357",
    "CVE-2017-2358",
    "CVE-2017-2360",
    "CVE-2017-2361",
    "CVE-2017-2370",
    "CVE-2017-2371"
  );
  script_bugtraq_id(
    93594,
    93781,
    94478,
    94845,
    94865,
    95723,
    95729,
    95731,
    95735
  );
  script_osvdb_id(
    125857,
    144365,
    145715,
    147407,
    147697,
    150757,
    150758,
    150759,
    150760,
    150763,
    150764,
    150775
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-01-23-2");

  script_name(english:"macOS 10.12.x < 10.12.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS that is 10.12.x prior to
10.12.3. It is, therefore, affected by multiple vulnerabilities in the
following components :

  - apache_mod_php
  - Bluetooth
  - Graphics Drivers
  - Help Viewer
  - IOAudioFamily
  - Kernel
  - libarchive
  - Vim
  - WebKit

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207483");
  # https://lists.apple.com/archives/security-announce/2017/Jan/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83c658ec");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.12.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
if (version !~ "^10\.12($|[^0-9])") audit(AUDIT_OS_NOT, "Mac OS 10.12.x");

fixed_version = "10.12.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    xss:TRUE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
