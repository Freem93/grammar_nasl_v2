#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);    # Avoid problems with large number of xrefs.


include("compat.inc");


if (description)
{
  script_id(56480);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2010-1634",
    "CVE-2010-2089",
    "CVE-2011-0185",
    "CVE-2011-0187",
    "CVE-2011-0226",
    "CVE-2011-0230",
    "CVE-2011-0260",
    "CVE-2011-1521",
    "CVE-2011-1755",
    "CVE-2011-1910",
    "CVE-2011-2464",
    "CVE-2011-2690",
    "CVE-2011-2691",
    "CVE-2011-2692",
    "CVE-2011-3192",
    "CVE-2011-3212",
    "CVE-2011-3213",
    "CVE-2011-3215",
    "CVE-2011-3216",
    "CVE-2011-3219",
    "CVE-2011-3220",
    "CVE-2011-3221",
    "CVE-2011-3222",
    "CVE-2011-3223",
    "CVE-2011-3225",
    "CVE-2011-3226",
    "CVE-2011-3227",
    "CVE-2011-3228",
    "CVE-2011-3246",
    "CVE-2011-3435",
    "CVE-2011-3436",
    "CVE-2011-3437"
  );
  script_bugtraq_id(
    40370,
    40863,
    48007,
    48250,
    48566,
    48618,
    48619,
    48660,
    49303,
    50085,
    50092,
    50100,
    50101,
    50109,
    50112,
    50113,
    50114,
    50115,
    50116,
    50120,
    50121,
    50127,
    50129,
    50130,
    50131,
    50144,
    50146,
    50153  
  );
  script_osvdb_id(
    64957,
    65151,
    71330,
    71639,
    72540,
    73174,
    73605,
    73661,
    73982,
    73983,
    73984,
    74721,
    76322,
    76355,
    76356,
    76358,
    76361,
    76362,
    76363,
    76365,
    76366,
    76367,
    76369,
    76370,
    76371,
    76372,
    76374,
    76376,
    76377,
    76378,
    76379,
    76380
  );

  script_name(english:"Mac OS X 10.7.x < 10.7.2 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.7.x that is prior
to 10.7.2. This version contains numerous security-related fixes for
the following components :

  - Apache
  - Application Firewall
  - ATS
  - BIND
  - Certificate Trust Policy
  - CFNetwork
  - CoreMedia
  - CoreProcesses
  - CoreStorage
  - File Systems
  - iChat Server
  - Kernel
  - libsecurity
  - Open Directory
  - PHP
  - python
  - QuickTime
  - SMB File Server
  - X11"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-303/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-136/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523931/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5002");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Oct/msg00003.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

  exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item("Host/OS");
  if (isnull(os)) exit(0, "The 'Host/OS' KB item is missing.");
  if ("Mac OS X" >!< os) exit(0, "The host does not appear to be running Mac OS X.");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


if (ereg(pattern:"Mac OS X 10\.7($|\.[0-1]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
