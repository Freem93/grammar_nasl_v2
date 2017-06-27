#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3004) exit(0);    # a large number of xrefs.
if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15898);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/03/05 23:04:26 $");

 script_cve_id("CVE-2004-1082", "CVE-2003-0020", "CVE-2003-0987", "CVE-2004-0174", "CVE-2004-0488", 
               "CVE-2004-0492", "CVE-2004-0885", "CVE-2004-0940", "CVE-2004-1083", "CVE-2004-1084", 
               "CVE-2004-0747", "CVE-2004-0786", "CVE-2004-0751", "CVE-2004-0748", "CVE-2004-1081", 
               "CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-1089", "CVE-2004-1085", 
               "CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772", "CVE-2004-1088", 
               "CVE-2004-1086", "CVE-2004-1123", "CVE-2004-1121", "CVE-2004-1122", "CVE-2004-1087");
 script_bugtraq_id(9921, 9930, 9571, 11471, 11360, 11469, 10508, 11802);
 script_osvdb_id(
  3819,
  4382,
  4383,
  6472,
  6839,
  9406,
  9407,
  9408,
  9409,
  9523,
  9742,
  9991,
  9994,
  10637,
  10750,
  10751,
  10909,
  11003,
  12176,
  12192,
  12193,
  12194,
  12198,
  12199,
  12200,
  12201,
  12202,
  12203,
  12206,
  12207,
  12881
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-12-02)");
 script_summary(english:"Check for Security Update 2004-12-02");
 
 script_set_attribute( attribute:"synopsis",  value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",   value:
"The remote host is missing Security Update 2004-12-02. This security
update contains a number of fixes for the following programs :

  - Apache
  - Apache2
  - AppKit
  - Cyrus IMAP
  - HIToolbox
  - Kerberos
  - Postfix
  - PSNormalizer
  - QuickTime Streaming Server
  - Safari
  - Terminal

These programs contain multiple vulnerabilities that could allow a
remote attacker to execute arbitrary code." );
 # http://web.archive.org/web/20080915104713/http://support.apple.com/kb/HT1646?
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?210abeb5"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-12-02."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/12/02");
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
# MacOS X 10.2.8, 10.3.6 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.6\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-12-02", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.([7-9]|[0-9][0-9]\.|[8-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
   set_kb_item(name:"CVE-2004-1082", value:TRUE);
   set_kb_item(name:"CVE-2003-0020", value:TRUE);
   set_kb_item(name:"CVE-2003-0987", value:TRUE);
   set_kb_item(name:"CVE-2004-0174", value:TRUE);
   set_kb_item(name:"CVE-2004-0488", value:TRUE);
   set_kb_item(name:"CVE-2004-0492", value:TRUE);
   set_kb_item(name:"CVE-2004-0885", value:TRUE);
   set_kb_item(name:"CVE-2004-0940", value:TRUE);
   set_kb_item(name:"CVE-2004-1083", value:TRUE);
   set_kb_item(name:"CVE-2004-1084", value:TRUE);
   set_kb_item(name:"CVE-2004-0747", value:TRUE);
   set_kb_item(name:"CVE-2004-0786", value:TRUE);
   set_kb_item(name:"CVE-2004-0751", value:TRUE);
   set_kb_item(name:"CVE-2004-0748", value:TRUE);
   set_kb_item(name:"CVE-2004-1081", value:TRUE);
   set_kb_item(name:"CVE-2004-0803", value:TRUE);
   set_kb_item(name:"CVE-2004-0804", value:TRUE);
   set_kb_item(name:"CVE-2004-0886", value:TRUE);
   set_kb_item(name:"CVE-2004-1089", value:TRUE);
   set_kb_item(name:"CVE-2004-1085", value:TRUE);
   set_kb_item(name:"CVE-2004-0642", value:TRUE);
   set_kb_item(name:"CVE-2004-0643", value:TRUE);
   set_kb_item(name:"CVE-2004-0644", value:TRUE);
   set_kb_item(name:"CVE-2004-0772", value:TRUE);
   set_kb_item(name:"CVE-2004-1088", value:TRUE);
   set_kb_item(name:"CVE-2004-1086", value:TRUE);
   set_kb_item(name:"CVE-2004-1123", value:TRUE);
   set_kb_item(name:"CVE-2004-1121", value:TRUE);
   set_kb_item(name:"CVE-2004-1122", value:TRUE);
   set_kb_item(name:"CVE-2004-1087", value:TRUE);
}
