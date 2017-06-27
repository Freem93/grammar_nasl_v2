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
 script_id(36533);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 5.6 (sparc) : 112535-03");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 112535-03");
 script_set_attribute(attribute: "description", value:
'SEAM 1.0: patch for Solaris 2.6_x86.
Date this patch was last updated by Sun : Nov/13/03');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/112535-03");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_end_attributes();

 script_summary(english: "Check for patch 112535-03");
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

e +=  solaris_check_patch(release:"5.6", arch:"i386", patch:"112535-03", obsoleted_by:"", package:"SUNWkrgdo", version:"5.6.0,REV=99.06.23.11.55");
e +=  solaris_check_patch(release:"5.6", arch:"i386", patch:"112535-03", obsoleted_by:"", package:"SUNWkrggl", version:"5.6.0,REV=99.06.23.11.55");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
