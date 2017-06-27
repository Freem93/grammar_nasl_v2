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
 script_id(36777);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 8 (sparc) : 110460-32");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 110460-32");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8: fruid/PICL plug-ins patch.
Date this patch was last updated by Sun : Nov/17/03');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/110460-32");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_end_attributes();

 script_summary(english: "Check for patch 110460-32");
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

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"FJSVpiclu", version:"11.8.0,REV=2002.10.24.16.51");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"SUNWfruid", version:"11.8.0,REV=2001.01.19.01.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"SUNWfruip", version:"11.8.0,REV=2001.01.19.01.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"SUNWfruix", version:"11.8.0,REV=2001.01.19.01.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"SUNWpiclh", version:"11.8.0,REV=2000.07.05.13.22");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"SUNWpiclu", version:"11.8.0,REV=2000.08.15.00.06");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110460-32", obsoleted_by:"108528-29 ", package:"SUNWpiclx", version:"11.8.0,REV=2000.07.05.13.22");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
