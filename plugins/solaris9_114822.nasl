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
 script_id(23502);
 script_version("$Revision: 1.10 $");

 script_name(english: "Solaris 5.9 (sparc) : 114822-05");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 114822-05");
 script_set_attribute(attribute: "description", value:
'GNOME 2.0.2: 64bit libpng Patch.
Date this patch was last updated by Sun : Sep/29/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/114822-05");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_end_attributes();

 script_summary(english: "Check for patch 114822-05");
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

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114822-05", obsoleted_by:"", package:"SUNWpngx", version:"2.0.2,REV=9.4.2003.05.14.06.42");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
