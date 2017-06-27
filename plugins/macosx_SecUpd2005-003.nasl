#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17587);
 script_version ("$Revision: 1.22 $");

 if (NASL_LEVEL >= 3000)
 {
  script_cve_id("CVE-2002-1347", "CVE-2004-0884", "CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013",
                "CVE-2004-1015", "CVE-2004-1067", "CVE-2005-0202", "CVE-2005-0235", "CVE-2005-0340", 
                "CVE-2005-0712", "CVE-2005-0713", "CVE-2005-0715", "CVE-2005-0716");
 }
 script_bugtraq_id(6347, 12478, 12863, 13224, 13220, 13226, 13237);
 script_osvdb_id(
  10555,
  10655,
  10656,
  10657,
  12096,
  12097,
  12098,
  12290,
  12348,
  13671,
  13780,
  15005,
  15006,
  15007,
  15008
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-003)");
 script_summary(english:"Check for Security Update 2005-003");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",  value:
"The remote host is missing Security Update 2005-003. This security
update contains security fixes for the following applications :

  - AFP Server
  - Bluetooth Setup Assistant
  - Core Foundation
  - Cyrus IMAP
  - Cyrus SASL
  - Folder Permissions
  - Mailman
  - Safari

These programs have multiple vulnerabilities which may allow a remote
attacker to execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA22971"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-003."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/08");
 script_cvs_date("$Date: 2016/05/20 14:12:05 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/03/28");
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
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[78]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-003", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.(9\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 foreach cve (make_list("CVE-2005-0340", "CVE-2005-0715", "CVE-2005-0716", "CVE-2005-0713", "CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013", "CVE-2004-1015", "CVE-2004-1067", "CVE-2002-1347", "CVE-2004-0884", "CVE-2005-0712", "CVE-2005-0202", "CVE-2005-0235" ))
	{
	set_kb_item(name:cve, value:TRUE);
	}
}
