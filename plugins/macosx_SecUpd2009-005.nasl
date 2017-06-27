#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");


if (description)
{
  script_id(40945);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id("CVE-2008-2079", "CVE-2008-5498", "CVE-2008-6680", "CVE-2009-0590", "CVE-2009-0591",
                "CVE-2009-0789", "CVE-2009-0949", "CVE-2009-1241", "CVE-2009-1270", "CVE-2009-1271",
                "CVE-2009-1272", "CVE-2009-1371", "CVE-2009-1372", "CVE-2009-1862", "CVE-2009-1863",
                "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866", "CVE-2009-1867", "CVE-2009-1868",
                "CVE-2009-1869", "CVE-2009-1870", "CVE-2009-2468", "CVE-2009-2800", "CVE-2009-2803",
                "CVE-2009-2804", "CVE-2009-2805", "CVE-2009-2807", "CVE-2009-2809", "CVE-2009-2811",
                "CVE-2009-2812", "CVE-2009-2813", "CVE-2009-2814");
  script_bugtraq_id(
    29106,
    33002,
    34256,
    34357,
    35759,
    36350,
    36354,
    36355,
    36357,
    36358,
    36359,
    36360,
    36361,
    36363,
    36364
  );
  script_osvdb_id(
    44937,
    51031,
    52486,
    52864,
    52865,
    52866,
    53440,
    53461,
    53597,
    53598,
    53602,
    53603,
    55002,
    56282,
    56385,
    56771,
    56772,
    56773,
    56774,
    56775,
    56776,
    56777,
    56778,
    57947,
    57948,
    57949,
    57950,
    57951,
    57952,
    57953,
    57954,
    57955,
    57956
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2009-005)");
  script_summary(english:"Check for the presence of Security Update 2009-005");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that
does not have Security Update 2009-005 applied.

This security update contains fixes for the following products :

  - Alias Manager
  - CarbonCore
  - ClamAV
  - ColorSync
  - CoreGraphics
  - CUPS
  - Flash Player plug-in
  - ImageIO
  - Launch Services
  - MySQL
  - PHP
  - SMB
  - Wiki Server"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3865"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17867"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2009-005 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 59, 79, 94, 119, 189, 200, 264, 287, 399);
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}

#

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

  if (egrep(pattern:"^SecUpd(Srvr)?(2009-00[5-9]|20[1-9][0-9]-)", string:packages))
    exit(0, "The host has Security Update 2009-005 or later installed and therefore is not affected.");
  else
    security_hole(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-8]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2009\.00[5-9]|20[1-9][0-9]\.[0-9]+)\.bom", string:packages))
    exit(0, "The host has Security Update 2009-005 or later installed and therefore is not affected.");
  else
    security_hole(0);
}
else exit(0, "The host is not affected.");
