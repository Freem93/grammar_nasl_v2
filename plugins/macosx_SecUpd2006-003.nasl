#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21341);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2014/03/06 01:32:41 $");

  script_cve_id("CVE-2006-1439", "CVE-2006-1982", "CVE-2006-1983", "CVE-2006-1984", "CVE-2006-1985",
                "CVE-2006-1440", "CVE-2006-1441", "CVE-2006-1442", "CVE-2006-1614", "CVE-2006-1615",
                "CVE-2006-1630", "CVE-2006-1443", "CVE-2006-1444", "CVE-2006-1448", "CVE-2006-1445",
                "CVE-2005-2628", "CVE-2006-0024", "CVE-2006-1552", "CVE-2006-1446", "CVE-2006-1447",
                "CVE-2005-4077", "CVE-2006-1449", "CVE-2006-1450", "CVE-2006-1451", "CVE-2006-1452",
                "CVE-2006-1453", "CVE-2006-1454", "CVE-2006-1455", "CVE-2006-1456", "CVE-2005-2337",
                "CVE-2006-1457");
 script_bugtraq_id(17634, 17951);
 script_osvdb_id(
  18825,
  19610,
  21509,
  23908,
  24457,
  24458,
  24459,
  24819,
  24821,
  24822,
  25516,
  25517,
  25583,
  25584,
  25585,
  25586,
  25587,
  25588,
  25589,
  25590,
  25591,
  25592,
  25593,
  25594,
  25595,
  25596,
  25597,
  25598,
  25599,
  25600,
  31837
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-003)");
 script_summary(english:"Check for Security Update 2006-003");

 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a vendor-supplied patch.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks
Security Update 2006-003.

This security update contains fixes for the following
applications :

AppKit
ImageIO
BOM
CFNetwork
ClamAV (Mac OS X Server only)
CoreFoundation
CoreGraphics
Finder
FTPServer
Flash Player
KeyCHain
LaunchServices
libcurl
Mail
MySQL Manager (Mac OS X Server only)
Preview
QuickDraw
QuickTime Streaming Server
Ruby
Safari");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303737");
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
http://support.apple.com/downloads/Security_Update_2006_003_Mac_OS_X_10_4_6_Client__PPC_
http://support.apple.com/downloads/Security_Update_2006_003_Mac_OS_X_10_4_6_Client__Intel_

Mac OS X 10.3 :
http://support.apple.com/downloads/Security_Update_2006_003__10_3_9_Client_
http://support.apple.com/downloads/Security_Update_2006_003__10_3_9_Server_");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/05/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-6]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-00[3467]|2007-003)", string:packages)) security_hole(0);
}
