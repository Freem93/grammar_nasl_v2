#
# (C) Tenable Network Security, Inc.
#

# better URL in solution, preserving old:
#http://www.apple.com/downloads/macosx/apple/securityupdate__2004-05-03_(10_3_3_Client).html
#http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-03_(10_2_8_Client).html
#http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-03_(10_2_8_Server).html
#http://www.apple.com/downloads/macosx/apple/securityupdate.html
               
if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12518);
 script_version ("$Revision: 1.16 $");
 script_cve_id(
   "CVE-2004-0020",
   "CVE-2004-0113",
   "CVE-2004-0155",
   "CVE-2004-0174",
   "CVE-2004-0392",
   "CVE-2004-0403", 
   "CVE-2004-0428",
   "CVE-2004-0430"
 );
 script_osvdb_id(4182, 4382, 4383, 5008, 5491, 5762, 5893, 6537);

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-05-03)");
 script_summary(english:"Check for Security Update 2004-05-03");
 
 script_set_attribute(
   attribute:"synopsis",
   value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(
   attribute:"description", 
   value:
"The remote host is missing Security Update 2004-05-03.
This security update includes updates for AFP Server, CoreFoundation,
and IPSec.

It also includes Security Update 2004-04-05, which includes updates
for CUPS, libxml2, Mail, and OpenSSL.

For Mac OS X 10.2.8, it also includes updates for Apache 1.3,
cd9660.util, Classic, CUPS, Directory Services, DiskArbitration,
fetchmail, fs_usage, gm4, groff, Mail, OpenSSL, Personal File Sharing,
PPP, rsync, Safari, System Configuration, System Initialization, and
zlib.

This update fixes various issues which may allow an attacker to
execute arbitrary code on the remote host." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://lists.apple.com/archives/security-announce/2004/May/msg00000.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-05-03."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'AppleFileServer LoginExt PathName Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/05/03");
 script_cvs_date("$Date: 2013/11/27 17:20:55 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
os    = get_kb_item("Host/MacOSX/Version");
if ( egrep(pattern:"Mac OS X 10\.3.* Server", string:os) ) exit(0);

# MacOS X 10.2.8 and 10.3.3 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.3\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-05-03", string:packages) ) security_hole(0);
  else {
	set_kb_item(name:"CVE-2004-0174", value:TRUE);
	set_kb_item(name:"CVE-2003-0020", value:TRUE);
	set_kb_item(name:"CVE-2004-0079", value:TRUE);
	set_kb_item(name:"CVE-2004-0081", value:TRUE);
	set_kb_item(name:"CVE-2004-0112", value:TRUE);
	}
}
