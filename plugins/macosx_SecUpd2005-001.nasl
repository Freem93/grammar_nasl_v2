#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if(description)
{
 script_id(16251);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2005-0125", "CVE-2005-0126", "CVE-2004-0989", "CVE-2005-0127", "CVE-2003-0860", 
               "CVE-2003-0863", "CVE-2004-0594", "CVE-2004-0595", "CVE-2004-1018", "CVE-2004-1019", 
               "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065", "CVE-2004-1314", 
               "CVE-2004-1036");
 script_bugtraq_id(12367, 12366, 12297, 11857);
 script_osvdb_id(
  7870,
  7871,
  11179,
  11180,
  11324,
  11603,
  11669,
  11670,
  11671,
  12410,
  12411,
  12412,
  12413,
  12415,
  12600,
  12602,
  13180,
  13181,
  13182,
  13183,
  14932,
  34717
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-001)");
 script_summary(english:"Check for Security Update 2005-001");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(attribute:"description",   value:
"he remote host is missing Security Update 2005-001. This security
update contains a number of fixes for the following programs :

  - at commands
  - ColorSync
  - libxml2
  - Mail
  - PHP
  - Safari
  - SquirrelMail

These programs have multiple vulnerabilities which may allow a remote
attacker to execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA22859"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-001."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/16");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/01/26");
 script_cvs_date("$Date: 2016/06/24 14:42:21 $");
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
# MacOS X 10.2.8, 10.3.7 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.7\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2005-001", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.([8-9]\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 list = make_list("CVE-2005-0125", "CVE-2005-0126", "CVE-2004-0989", "CVE-2005-0127", "CVE-2003-0860", "CVE-2003-0863", "CVE-2004-0594", "CVE-2004-0595", "CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065", "CVE-2004-1314", "CVE-2004-1036");
 foreach cve (list) set_kb_item(name:cve, value:TRUE);
}
