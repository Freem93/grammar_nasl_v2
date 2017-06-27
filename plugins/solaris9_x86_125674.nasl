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
 script_id(29212);
 script_version("$Revision: 1.7 $");

 script_name(english: "Solaris 5.9 (x86) : 125674-02");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125674-02");
 script_set_attribute(attribute: "description", value:
'GNOME 2.0.2_x86: SUNWTiff libtiff library patch.
Date this patch was last updated by Sun : Aug/29/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/125674-02");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/04");
 script_end_attributes();

 script_summary(english: "Check for patch 125674-02");
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

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125674-02", obsoleted_by:"", package:"SUNWTiff", version:"11.9.0,REV=2002.03.02.00.30");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"125674-02", obsoleted_by:"", package:"SUNWTiffS", version:"11.9.0,REV=2002.03.02.00.30");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
