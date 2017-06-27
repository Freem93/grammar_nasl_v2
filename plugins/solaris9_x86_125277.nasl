# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(25545);
 script_version("$Revision: 1.10 $");

 script_name(english: "Solaris 5.9 (x86) : 125277-08");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125277-08");
 script_set_attribute(attribute: "description", value:
'Directory Server Enterprise Edition 6.3.1 : SunOS 5.9_x86 Native P.
Date this patch was last updated by Sun : Feb/09/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/125277-08");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/18");
 script_end_attributes();

 script_summary(english: "Check for patch 125277-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-console-agent", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-console-cli", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-console-common", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-console-gui-help", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-console-gui", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-directory-client", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-directory-config", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-directory-dev", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-directory-ha", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-directory-man", version:"6.0,REV=2006.11.06.18.13");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-directory", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-proxy-client", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-proxy-config", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-proxy-man", version:"6.0,REV=2006.11.06.18.13");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-proxy", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125277-08", obsoleted_by:"", package:"SUNWldap-shared", version:"6.0,REV=2007.01.25");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
