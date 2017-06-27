#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24354);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2007-0021", "CVE-2007-0023", "CVE-2007-0197", "CVE-2007-0613", "CVE-2007-0614", "CVE-2007-0710");
 script_bugtraq_id(21980, 22146, 22188, 22304);
 script_osvdb_id(32695, 32698, 32699, 32713, 32714, 32715);

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2007-002)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes several
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2007-002 applied. 

This update fixes security flaws in the following applications :

- Finder
- iChat
- UserNotification" );
 # http://web.archive.org/web/20080110231039/http://docs.info.apple.com/article.html?artnum=305102
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22a97335" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2007-002 :

http://www.apple.com/support/downloads/securityupdate2007002universal.html
http://www.apple.com/support/downloads/securityupdate2007002panther.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 119, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/09");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/02/15");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the presence of the SecUpdate 2007-002");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);



uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-8]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2007-00[2-9]|200[89]-|20[1-9][0-9]-)", string:packages)) 
    security_hole(0);
}
