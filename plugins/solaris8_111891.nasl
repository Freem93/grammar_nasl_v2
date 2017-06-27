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
 script_id(23337);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 5.8 (sparc) : 111891-10");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 111891-10");
 script_set_attribute(attribute: "description", value:
'Sun Ray Server version 1.3 Patch Update.
Date this patch was last updated by Sun : Aug/01/03');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/111891-10");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2003/08/01");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:18 $");
 script_end_attributes();

 script_summary(english: "Check for patch 111891-10");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWbbchr", version:"1.0_14.a,REV=2001.07.16.20.33");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWuta", version:"1.3_12.c,REV=2001.07.16.20.52");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWutesa", version:"1.3_12.c,REV=2001.07.16.20.52");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWuto", version:"1.3_12.c,REV=2001.07.16.20.52");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWutps", version:"1.3_12.c,REV=2001.07.16.20.52");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWutr", version:"1.3_12.c,REV=2001.07.16.20.52");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWutscr", version:"1.3_12.c,REV=2001.07.16.20.52");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111891-10", obsoleted_by:"", package:"SUNWutu", version:"1.3_12.c,REV=2001.07.16.20.52");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
