#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3004 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(24811);
 script_version ("$Revision: 1.28 $");

 script_cve_id("CVE-2007-0719", "CVE-2007-0467", "CVE-2007-0720", 
               "CVE-2007-0721", "CVE-2007-0722", "CVE-2006-6061", 
               "CVE-2006-6062", "CVE-2006-5679", "CVE-2007-0229", 
               "CVE-2007-0267", "CVE-2007-0299", "CVE-2007-0723", 
               "CVE-2006-5330", "CVE-2006-0300", "CVE-2006-6097", 
               "CVE-2007-0318", "CVE-2007-0724", "CVE-2007-1071", 
               "CVE-2007-0733", "CVE-2006-5836", "CVE-2006-6129", 
               "CVE-2006-6173", "CVE-2006-1516", "CVE-2006-1517", 
               "CVE-2006-2753", "CVE-2006-3081", "CVE-2006-4031", 
               "CVE-2006-4226", "CVE-2006-3469", "CVE-2006-6130", 
               "CVE-2007-0236", "CVE-2007-0726", "CVE-2006-0225", 
               "CVE-2006-4924", "CVE-2006-5051", "CVE-2006-5052", 
               "CVE-2007-0728", "CVE-2007-0588", "CVE-2007-0730", 
               "CVE-2007-0731", "CVE-2007-0463", "CVE-2005-2959", 
               "CVE-2006-4829");
 script_bugtraq_id(20982, 21236, 21291, 21349, 22041, 22948);
 script_osvdb_id(
  20303,
  22692,
  23371,
  25226,
  25228,
  25987,
  27054,
  27416,
  27703,
  28012,
  28834,
  29152,
  29264,
  29266,
  29863,
  30196,
  30216,
  30509,
  30510,
  30706,
  30721,
  30722,
  30723,
  31653,
  32684,
  32685,
  32686,
  32687,
  32703,
  32706,
  33365,
  34072,
  34845,
  34846,
  34847,
  34848,
  34849,
  34850,
  34851,
  34852,
  34853,
  34854,
  34855
 );

 script_name(english:"Mac OS X < 10.4.9 Multiple Vulnerabilities (Security Update 2007-003)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.9 or a version of Mac OS X 10.3 which does not have 
Security Update 2007-003 applied.

This update contains several security fixes for the following programs :

 - ColorSync
 - CoreGraphics
 - Crash Reporter
 - CUPS
 - Disk Images
 - DS Plugins
 - Flash Player
 - GNU Tar
 - HFS
 - HID Family
 - ImageIO
 - Kernel
 - MySQL server
 - Networking
 - OpenSSH
 - Printing
 - QuickDraw Manager
 - servermgrd
 - SMB File Server
 - Software Update
 - sudo 
 - WebLog" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305214" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 : Upgrade to Mac OS X 10.4.9 :

http://www.apple.com/support/downloads/macosxserver1049updateppc.html
http://www.apple.com/support/downloads/macosx1049updateintel.html
http://www.apple.com/support/downloads/macosxserver1049updateuniversal.html

Mac OS X 10.3 : Apply Security Update 2007-003 :

http://www.apple.com/support/downloads/securityupdate20070031039client.html
http://www.apple.com/support/downloads/securityupdate20070031039server.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79, 119, 362, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/28");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/03/13");
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
script_set_attribute(attribute:"plugin_type", value:"combined");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	 os = get_kb_item("Host/OS");
	 confidence = get_kb_item("Host/OS/Confidence");
	 if ( confidence <= 90 ) exit(0);
	}
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-8]([^0-9]|$))", string:os)) security_hole(0);
else if ( ereg(pattern:"Mac OS X 10\.3\.", string:os) )
{
 packages = get_kb_item("Host/MacOSX/packages");
 if ( ! packages ) exit(0);
 if (!egrep(pattern:"^SecUpd(Srvr)?2007-003", string:packages)) security_hole(0);
}
