#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(25830);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");

 script_cve_id("CVE-2004-0996", "CVE-2004-2541", "CVE-2005-0758", "CVE-2005-2090", "CVE-2005-3128",
               "CVE-2006-2842", "CVE-2006-3174", "CVE-2006-4019", "CVE-2006-6142", "CVE-2007-0450",
               "CVE-2007-0478", "CVE-2007-1001", "CVE-2007-1262", "CVE-2007-1287", "CVE-2007-1358",
               "CVE-2007-1460", "CVE-2007-1461", "CVE-2007-1484", "CVE-2007-1521", "CVE-2007-1583",
               "CVE-2007-1711", "CVE-2007-1717", "CVE-2007-1860", "CVE-2007-2403", "CVE-2007-2404",
               "CVE-2007-2405", "CVE-2007-2406", "CVE-2007-2407", "CVE-2007-2408", "CVE-2007-2409",
               "CVE-2007-2410", "CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2446", "CVE-2007-2447",
               "CVE-2007-2589", "CVE-2007-2798", "CVE-2007-3742", "CVE-2007-3744", "CVE-2007-3745",
               "CVE-2007-3746", "CVE-2007-3747", "CVE-2007-3748", "CVE-2007-3944");
 script_bugtraq_id(11697, 13582, 23910, 23972, 23973, 24195, 24196, 24197, 24198, 24653, 25159);
 script_osvdb_id(
  11919,
  11920,
  16371,
  19723,
  25973,
  26610,
  27917,
  31720,
  31721,
  31722,
  32712,
  32774,
  33934,
  33935,
  33936,
  33938,
  33940,
  33946,
  33948,
  34671,
  34699,
  34700,
  34731,
  34732,
  34733,
  34769,
  34877,
  34881,
  35887,
  35888,
  35889,
  36451,
  36453,
  36595,
  36596,
  36597,
  36963,
  36964,
  36965,
  36966,
  36967,
  36968,
  36969,
  36970,
  36971,
  36972,
  36973,
  36974,
  36975,
  43452
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2007-007)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 or 10.3 which
does not have the security update 2007-007 applied. 

This update contains several security fixes for the following programs :

 - bzip2
 - CFNetwork
 - CoreAudio
 - cscope
 - gnuzip
 - iChat
 - Kerberos
 - mDNSResponder
 - PDFKit
 - PHP
 - Quartz Composer
 - Samba
 - SquirrelMail
 - Tomcat
 - WebCore
 - WebKit" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=306172" );
 script_set_attribute(attribute:"solution", value:
"Install the security update 2007-007 :

http://www.apple.com/support/downloads/securityupdate200700710410universal.html
http://www.apple.com/support/downloads/securityupdate20070071039.html
http://www.apple.com/support/downloads/securityupdate20070071039server.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(16, 20, 22, 59, 79, 119, 352);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/08/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/09");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_summary(english:"Check for the presence of the SecUpdate 2007-007");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);



uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-9]\.|8\.10\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2007-00[789]|200[89]-|20[1-9][0-9]-)", string:packages)) 
    security_hole(0);
}
