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
 script_id(32500);
 script_version("$Revision: 1.14 $");

 script_name(english: "Solaris 10 (x86) : 137018-03");
 script_osvdb_id(45885);
 script_cve_id("CVE-2008-2538");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 137018-03");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: crontab patch.
Date this patch was last updated by Sun : Jul/14/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/137018-03");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_cwe_id(362);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/02");
 script_cvs_date("$Date: 2011/09/18 00:54:23 $");
 script_end_attributes();

 script_summary(english: "Check for patch 137018-03");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137018-03", obsoleted_by:"140560-01 142910-17 138224-02 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137018-03", obsoleted_by:"140560-01 142910-17 138224-02 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137018-03", obsoleted_by:"140560-01 142910-17 138224-02 ", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137018-03", obsoleted_by:"140560-01 142910-17 138224-02 ", package:"SUNWxcu6", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
