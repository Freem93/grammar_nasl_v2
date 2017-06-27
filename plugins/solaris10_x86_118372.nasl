# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(20333);
 script_version("$Revision: 1.26 $");

 script_name(english: "Solaris 10 (x86) : 118372-10");
 script_osvdb_id(25356, 28549, 60995);
 script_cve_id("CVE-2005-3666", "CVE-2005-3667", "CVE-2005-3668", "CVE-2005-3674", "CVE-2006-2298", "CVE-2006-4339", "CVE-2006-5201", "CVE-2006-7140");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 118372-10");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: elfsign patch.
Date this patch was last updated by Sun : Apr/16/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/118372-10");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(310);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/20");
 script_cvs_date("$Date: 2011/09/18 00:54:22 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/08");
 script_end_attributes();

 script_summary(english: "Check for patch 118372-10");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118372-10", obsoleted_by:"120012-14 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118372-10", obsoleted_by:"120012-14 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118372-10", obsoleted_by:"120012-14 ", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
