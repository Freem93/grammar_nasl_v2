#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(45373);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2003-0063",
    "CVE-2006-1329",
    "CVE-2008-0564",
    "CVE-2008-0888",
    "CVE-2008-2712",
    "CVE-2008-4101",
    "CVE-2008-5302",
    "CVE-2008-5303",
    "CVE-2008-5515",
    "CVE-2009-0033",
    "CVE-2009-0037",
    "CVE-2009-0316",
    "CVE-2009-0580",
    "CVE-2009-0688",
    "CVE-2009-0689",
    "CVE-2009-0781",
    "CVE-2009-0783",
    "CVE-2009-1904",
    "CVE-2009-2042",
    "CVE-2009-2417",
    "CVE-2009-2422",
    "CVE-2009-2632",
    "CVE-2009-2693",
    "CVE-2009-2801",
    "CVE-2009-2901",
    "CVE-2009-2902",
    "CVE-2009-2906",
    "CVE-2009-3009",
    "CVE-2009-3095",
    "CVE-2009-3557",
    "CVE-2009-3558",
    "CVE-2009-3559",
    "CVE-2009-4142",
    "CVE-2009-4143",
    "CVE-2009-4214",
    "CVE-2010-0041",
    "CVE-2010-0042",
    "CVE-2010-0055",
    "CVE-2010-0056",
    "CVE-2010-0057",
    "CVE-2010-0058",
    "CVE-2010-0063",
    "CVE-2010-0065",
    "CVE-2010-0393",
    "CVE-2010-0497",
    "CVE-2010-0498",
    "CVE-2010-0500",
    "CVE-2010-0501",
    "CVE-2010-0502",
    "CVE-2010-0503",
    "CVE-2010-0504",
    "CVE-2010-0505",
    "CVE-2010-0506",
    "CVE-2010-0507",
    "CVE-2010-0508",
    "CVE-2010-0509",
    "CVE-2010-0510",
    "CVE-2010-0513",
    "CVE-2010-0521",
    "CVE-2010-0522",
    "CVE-2010-0523",
    "CVE-2010-0524",
    "CVE-2010-0525",
    "CVE-2010-0533"
  );
  script_bugtraq_id(
    6940,
    12767,
    17155,
    27630,
    28288,
    29715,
    30795,
    33447,
    33962,
    34961,
    35193,
    35196,
    35233,
    35263,
    35278,
    35416,
    35510,
    35579,
    36032,
    36278,
    36296,
    36377,
    36554,
    36555,
    36573,
    37142,
    37389,
    37390,
    37942,
    37944,
    37945,
    38524,
    38676,
    38677,
    39151,
    39156,
    39157,
    39169,
    39170,
    39171,
    39172,
    39175,
    39194,
    39231,
    39232,
    39234,
    39245,
    39252,
    39255,
    39256,
    39264,
    39268,
    39273,
    39274,
    39277,
    39279,
    39281,
    39289,
    39290,
    39292
  );
  script_osvdb_id(
    24009,
    41088,
    41089,
    43332,
    46306,
    50446,
    51435,
    51437,
    52899,
    53373,
    53572,
    54514,
    54515,
    54915,
    55031,
    55053,
    55054,
    55055,
    55056,
    55603,
    55664,
    56994,
    57666,
    57843,
    57882,
    58103,
    58519,
    60279,
    60434,
    60435,
    60436,
    60544,
    61208,
    61209,
    62052,
    62053,
    62054,
    62715,
    62934,
    62935,
    63360,
    63366,
    63370,
    63371,
    63373,
    63377,
    63378,
    63380,
    63382,
    63383,
    63385,
    63386,
    63387,
    63389,
    63391,
    63392,
    63393,
    63395,
    63397,
    63398,
    63399,
    63402,
    63404,
    63405,
    63407,
    63408,
    63409,
    63639
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2010-002)");
  script_summary(english:"Check for the presence of Security Update 2010-002");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.5 that does not
have Security Update 2010-002 applied.

This security update contains fixes for the following products :

  - AppKit
  - Application Firewall
  - AFP Server
  - Apache
  - ClamAV
  - CoreTypes
  - CUPS
  - curl
  - Cyrus IMAP
  - Cyrus SASL
  - Disk Images
  - Directory Services
  - Event Monitor
  - FreeRADIUS
  - FTP Server
  - iChat Server
  - Image RAW
  - Libsystem
  - Mail
  - Mailman
  - OS Services
  - Password Server
  - perl
  - PHP
  - PS Normalizer
  - Ruby
  - Server Admin
  - SMB
  - Tomcat
  - unzip
  - vim
  - Wiki Server
  - X11
  - xar"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4077"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/19364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2010-002 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 79, 119, 189, 200, 264, 287, 310, 352, 362);
script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^9\.[0-8]\.", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2010\.00[2-9]|201[1-9]\.[0-9]+)(\.leopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2010-002 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
