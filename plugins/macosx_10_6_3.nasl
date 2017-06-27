#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(45372);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2003-0063",
    "CVE-2006-1329",
    "CVE-2008-4456",
    "CVE-2008-5515",
    "CVE-2008-7247",
    "CVE-2009-0033",
    "CVE-2009-0580",
    "CVE-2009-0689",
    "CVE-2009-0781",
    "CVE-2009-0783",
    "CVE-2009-1904",
    "CVE-2009-2042",
    "CVE-2009-2417",
    "CVE-2009-2422",
    "CVE-2009-2446",
    "CVE-2009-2693",
    "CVE-2009-2901",
    "CVE-2009-2902",
    "CVE-2009-2906",
    "CVE-2009-3009",
    "CVE-2009-3095",
    "CVE-2009-3557",
    "CVE-2009-3558",
    "CVE-2009-3559",
    "CVE-2009-4017",
    "CVE-2009-4019",
    "CVE-2009-4030",
    "CVE-2009-4214",
    "CVE-2010-0041",
    "CVE-2010-0042",
    "CVE-2010-0043",
    "CVE-2010-0057",
    "CVE-2010-0059",
    "CVE-2010-0060",
    "CVE-2010-0062",
    "CVE-2010-0063",
    "CVE-2010-0064",
    "CVE-2010-0065",
    "CVE-2010-0393",
    "CVE-2010-0497",
    "CVE-2010-0498",
    "CVE-2010-0500",
    "CVE-2010-0501",
    "CVE-2010-0502",
    "CVE-2010-0504",
    "CVE-2010-0505",
    "CVE-2010-0507",
    "CVE-2010-0508",
    "CVE-2010-0509",
    "CVE-2010-0510",
    "CVE-2010-0511",
    "CVE-2010-0512",
    "CVE-2010-0513",
    "CVE-2010-0514",
    "CVE-2010-0515",
    "CVE-2010-0516",
    "CVE-2010-0517",
    "CVE-2010-0518",
    "CVE-2010-0519",
    "CVE-2010-0520",
    "CVE-2010-0521",
    "CVE-2010-0524",
    "CVE-2010-0525",
    "CVE-2010-0526",
    "CVE-2010-0533",
    "CVE-2010-0534",
    "CVE-2010-0535",
    "CVE-2010-0537"
  );
  script_bugtraq_id(
    6940,
    17155,
    31486,
    35193,
    35196,
    35233,
    35263,
    35278,
    35416,
    35510,
    35579,
    35609,
    36032,
    36278,
    36554,
    36555,
    36573,
    37075,
    37142,
    37297,
    37942,
    37944,
    37945,
    38043,
    38524,
    38673,
    38676,
    38677,
    39151,
    39153,
    39157,
    39160,
    39161,
    39171,
    39172,
    39175,
    39194,
    39230,
    39231,
    39232,
    39234,
    39236,
    39252,
    39255,
    39256,
    39258,
    39264,
    39268,
    39273,
    39274,
    39278,
    39279,
    39281,
    39291
  );
  script_osvdb_id(
    24009,
    48710,
    52899,
    54915,
    55031,
    55053,
    55054,
    55055,
    55056,
    55603,
    55664,
    55734,
    56994,
    57666,
    57882,
    58519,
    60279,
    60434,
    60435,
    60436,
    60451,
    60488,
    60489,
    60544,
    60664,
    60665,
    62052,
    62053,
    62054,
    62715,
    62934,
    62935,
    62936,
    63359,
    63360,
    63365,
    63366,
    63369,
    63371,
    63372,
    63373,
    63374,
    63376,
    63377,
    63378,
    63379,
    63381,
    63383,
    63384,
    63385,
    63386,
    63388,
    63389,
    63390,
    63392,
    63393,
    63394,
    63395,
    63396,
    63398,
    63399,
    63400,
    63401,
    63403,
    63404,
    63405,
    63406,
    63408,
    63409,
    63639
  );

  script_name(english:"Mac OS X 10.6.x < 10.6.3 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6.x that is prior
to 10.6.3.

Mac OS X 10.6.3 contains security fixes for the following products :

  - AFP Server
  - Apache
  - CoreAudio
  - CoreMedia
  - CoreTypes
  - CUPS
  - DesktopServices
  - Disk Images
  - Directory Services
  - Dovecot
  - Event Monitor
  - FreeRADIUS
  - FTP Server
  - iChat Server
  - ImageIO
  - Image RAW
  - Libsystem
  - Mail
  - MySQL
  - OS Services
  - Password Server
  - PHP
  - Podcast Producer
  - Preferences
  - PS Normalizer
  - QuickTime
  - Ruby
  - Server Admin
  - SMB
  - Tomcat
  - Wiki Server
  - X11"
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
    value:"Upgrade to Mac OS X 10.6.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 59, 79, 119, 134, 189, 200, 264, 287, 310);
script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item("Host/OS");
  c = get_kb_item("Host/OS/Confidence");
  if ( isnull(os) || c <= 70 ) exit(0);
}
if (!os) exit(1, "The 'Host/OS' KB item is missing.");


if (ereg(pattern:"Mac OS X 10\.6($|\.[0-2]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
