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
 script_id(42099);
 script_version("$Revision: 1.7 $");

 script_name(english: "Solaris 10 (sparc) : 141878-12");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141878-12");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: iSCSI patch.
Date this patch was last updated by Sun : Feb/24/10');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/141878-12");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/10/13");
 script_cvs_date("$Date: 2011/09/18 00:54:22 $");
 script_end_attributes();

 script_summary(english: "Check for patch 141878-12");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141878-12", obsoleted_by:"125388-02 143645-11 ", package:"SUNWiscsir", version:"11.10.0,REV=2005.01.04.14.31");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141878-12", obsoleted_by:"125388-02 143645-11 ", package:"SUNWiscsiu", version:"11.10.0,REV=2005.01.04.14.31");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
