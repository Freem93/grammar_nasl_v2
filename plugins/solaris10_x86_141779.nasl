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
 script_id(39765);
 script_version("$Revision: 1.5 $");

 script_name(english: "Solaris 10 (x86) : 141779-05");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141779-05");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: lp patch.
Date this patch was last updated by Sun : Jul/30/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/141779-05");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/07/09");
 script_end_attributes();

 script_summary(english: "Check for patch 141779-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141779-05", obsoleted_by:"141445-09 ", package:"SUNWippcore", version:"13.1,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141779-05", obsoleted_by:"141445-09 ", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141779-05", obsoleted_by:"141445-09 ", package:"SUNWpcu", version:"13.1,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141779-05", obsoleted_by:"141445-09 ", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141779-05", obsoleted_by:"141445-09 ", package:"SUNWpsm-ipp", version:"11.10.0.0,REV=2008.02.29.14.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141779-05", obsoleted_by:"141445-09 ", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141779-05", obsoleted_by:"141445-09 ", package:"SUNWpsu", version:"13.1,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
