#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if(description)
{
 script_id(18189);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/05/17 16:53:09 $");

 script_cve_id("CVE-2004-0687", "CVE-2004-0688", "CVE-2004-1051", "CVE-2004-1307", "CVE-2004-1308",
                "CVE-2005-0342", "CVE-2005-0594", "CVE-2005-1330", "CVE-2005-1331", "CVE-2005-1332",
                "CVE-2005-1333", "CVE-2005-1335", "CVE-2005-1336", "CVE-2005-1337", "CVE-2005-1338",
                "CVE-2005-1339", "CVE-2005-1340", "CVE-2005-1341", "CVE-2005-1342", "CVE-2005-1343",
                "CVE-2005-1344");
 script_bugtraq_id(13503, 13502, 13500, 13496, 13494, 13491, 13488, 13486, 13480);
 script_osvdb_id(
  10026,
  10027,
  10028,
  10029,
  10030,
  10031,
  10032,
  10033,
  10034,
  11716,
  12555,
  12556,
  12848,
  13617,
  16071,
  16072,
  16073,
  16074,
  16075,
  16077,
  16078,
  16079,
  16080,
  16081,
  16082,
  16083,
  16084,
  16085
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-005)");
 script_summary(english:"Check for Security Update 2005-005");

 script_set_attribute( attribute:"synopsis",  value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",  value:
"The remote host is missing Security Update 2005-005. This security
update contains fixes for the following applications :

  - Apache
  - AppKit
  - AppleScript
  - Bluetooth
  - Directory Services
  - Finder
  - Foundation
  - HelpViewer
  - LDAP
  - libXpm
  - lukemftpd
  - NetInfo
  - ServerAdmin
  - sudo
  - Terminal
  - VPN

These programs have multiple vulnerabilities that could allow a
remote attacker to execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA23185"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-005."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/15");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/06/09");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-005", string:packages)) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.[0-9][0-9]\.)", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 set_kb_item(name:"CVE-2005-0193", value:TRUE);
}
