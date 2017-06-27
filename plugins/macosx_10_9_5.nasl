#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77748);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2013-7345",
    "CVE-2014-0076",
    "CVE-2014-0185",
    "CVE-2014-0195",
    "CVE-2014-0207",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-0237",
    "CVE-2014-0238",
    "CVE-2014-1391",
    "CVE-2014-1943",
    "CVE-2014-2270",
    "CVE-2014-2525",
    "CVE-2014-3470",
    "CVE-2014-3478",
    "CVE-2014-3479",
    "CVE-2014-3480",
    "CVE-2014-3487",
    "CVE-2014-3515",
    "CVE-2014-3981",
    "CVE-2014-4049",
    "CVE-2014-4350",
    "CVE-2014-4374",
    "CVE-2014-4376",
    "CVE-2014-4377",
    "CVE-2014-4378",
    "CVE-2014-4379",
    "CVE-2014-4381",
    "CVE-2014-4388",
    "CVE-2014-4389",
    "CVE-2014-4390",
    "CVE-2014-4393",
    "CVE-2014-4394",
    "CVE-2014-4395",
    "CVE-2014-4396",
    "CVE-2014-4397",
    "CVE-2014-4398",
    "CVE-2014-4399",
    "CVE-2014-4400",
    "CVE-2014-4401",
    "CVE-2014-4402",
    "CVE-2014-4403",
    "CVE-2014-4416",
    "CVE-2014-4979"
  );
  script_bugtraq_id(
    65596,
    66002,
    66363,
    66406,
    66478,
    67118,
    67759,
    67765,
    67837,
    67898,
    67899,
    67900,
    67901,
    68007,
    68120,
    68237,
    68238,
    68239,
    68241,
    68243,
    68852,
    69888,
    69891,
    69892,
    69893,
    69894,
    69895,
    69896,
    69897,
    69898,
    69901,
    69903,
    69905,
    69906,
    69907,
    69908,
    69910,
    69915,
    69916,
    69921,
    69925,
    69931,
    69948,
    69950
  );
  script_osvdb_id(
    103424,
    104081,
    104208,
    104810,
    105027,
    106473,
    107725,
    107729,
    107730,
    107731,
    107732,
    107994,
    108462,
    108463,
    108464,
    108465,
    108466,
    108467,
    109476,
    111643
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-09-17-3");

  script_name(english:"Mac OS X 10.9.x < 10.9.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.9.x that is prior
to version 10.9.5. This update contains several security-related fixes
for the following components :

  - apache_mod_php
  - Bluetooth
  - CoreGraphics
  - Foundation
  - Intel Graphics Driver
  - IOAcceleratorFamily
  - IOHIDFamily
  - IOKit
  - Kernel
  - Libnotify
  - OpenSSL
  - QT Media Foundation
  - ruby

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533483/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6443");
  script_set_attribute(attribute:"see_also", value:"http://osdir.com/ml/general/2014-09/msg34124.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.9.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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

fixed_version = "10.9.5";
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
