#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);    # Avoid problems with large number of xrefs.


include("compat.inc");


if (description)
{
  script_id(56481);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2009-4022",
    "CVE-2010-0097",
    "CVE-2010-1157",
    "CVE-2010-1634",
    "CVE-2010-2089",
    "CVE-2010-2227",
    "CVE-2010-3436",
    "CVE-2010-3613",
    "CVE-2010-3614",
    "CVE-2010-3718",
    "CVE-2010-4172",
    "CVE-2010-4645",
    "CVE-2011-0013",
    "CVE-2011-0185",
    "CVE-2011-0224",
    "CVE-2011-0229",
    "CVE-2011-0230",
    "CVE-2011-0231",
    "CVE-2011-0249",
    "CVE-2011-0250",
    "CVE-2011-0251",
    "CVE-2011-0252",
    "CVE-2011-0259",
    "CVE-2011-0411",
    "CVE-2011-0419",
    "CVE-2011-0420",
    "CVE-2011-0421",
    "CVE-2011-0534",
    "CVE-2011-0707",
    "CVE-2011-0708",
    "CVE-2011-1092",
    "CVE-2011-1153",
    "CVE-2011-1466",
    "CVE-2011-1467",
    "CVE-2011-1468",
    "CVE-2011-1469",
    "CVE-2011-1470",
    "CVE-2011-1471",
    "CVE-2011-1521",
    "CVE-2011-1755",
    "CVE-2011-1910",
    "CVE-2011-2464",
    "CVE-2011-2690",
    "CVE-2011-2691",
    "CVE-2011-2692",
    "CVE-2011-3192",
    "CVE-2011-3213",
    "CVE-2011-3214",
    "CVE-2011-3217",
    "CVE-2011-3218",
    "CVE-2011-3219",
    "CVE-2011-3220",
    "CVE-2011-3221",
    "CVE-2011-3222",
    "CVE-2011-3223",
    "CVE-2011-3224",
    "CVE-2011-3228"
  );
  script_bugtraq_id(
    37118,
    37865,
    39635,
    40370,
    40863,
    41544,
    44723,
    45015,
    45133,
    45137,
    45668,
    46164,
    46174,
    46177,
    46354,
    46365,
    46429,
    46464,
    46767,
    46786,
    46854,
    46967,
    46968,
    46969,
    46970,
    46975,
    46977,
    48007,
    48250,
    48566,
    48618,
    48660,
    49303,
    50085,
    50091,
    50092,
    50095,
    50098,
    50100,
    50101,
    50111,
    50116,
    50117,
    50122,
    50127,
    50130,
    50131,
    50150  
  );
  script_osvdb_id(
    60493,
    61853,
    64023,
    64957,
    65151,
    66319,
    69110,
    69456,
    69558,
    69559,
    70370,
    70809,
    70936,
    71021,
    71330,
    71557,
    71558,
    71597,
    71598,
    72532,
    72533,
    72540,
    73174,
    73275,
    73383,
    73605,
    73622,
    73623,
    73624,
    73625,
    73626,
    73754,
    73755,
    73982,
    73983,
    73984,
    74270,
    74271,
    74272,
    74273,
    74721,
    76323,
    76355,
    76357,
    76358,
    76359,
    76360,
    76363,
    76364,
    76368,
    76372,
    76373,
    76374,
    76375,
    76377,
    76378,
    76379,
    76380
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2011-006)");
  script_summary(english:"Check for the presence of Security Update 2011-006");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6 that does not
have Security Update 2011-006 applied.  This update contains numerous
security-related fixes for the following components :

  - Apache
  - Application Firewall
  - ATS
  - BIND
  - Certificate Trust Policy
  - CFNetwork
  - CoreFoundation
  - CoreMedia
  - File Systems
  - IOGraphics
  - iChat Server
  - Mailman
  - MediaKit
  - PHP
  - postfix
  - python
  - QuickTime
  - Tomcat
  - User Documentation
  - Web Server
  - X11"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-295/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-303/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-136/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523931/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5002");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Oct/msg00003.html");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2011-006 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


if (ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os)) 
{
  packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2011\.00[6-9]|201[2-9]\.[0-9]+)(\.snowleopard[0-9.]*)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2011-006 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running "+os+" and therefore is not affected.");
