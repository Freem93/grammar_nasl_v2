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
 script_id(12652);
 script_version("$Revision: 1.13 $");

 script_name(english: "Solaris 2.5.1 (sparc) : 103582-24");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 103582-24");
 script_set_attribute(attribute: "description", value:
'SunOS 5.5.1: /kernel/drv/tcp and /usr/bin/netstat patch.
Date this patch was last updated by Sun : Oct/20/99');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/103582-24");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_end_attributes();

 script_summary(english: "Check for patch 103582-24");
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

e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103582-24", obsoleted_by:"", package:"SUNWcsr", version:"11.5.1,REV=96.05.02.21.09");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103582-24", obsoleted_by:"", package:"SUNWcsu", version:"11.5.1,REV=96.05.02.21.09");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
