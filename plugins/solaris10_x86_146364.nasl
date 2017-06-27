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
 script_id(51884);
 script_version("$Revision: 1.6 $");

 script_name(english: "Solaris 10 (x86) : 146364-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 146364-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: Samba patch.
Date this patch was last updated by Sun : Jan/04/11');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/146364-01");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "patch_publication_date", value: "2011/01/04");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/02/05");
 script_cvs_date("$Date: 2011/09/18 00:54:24 $");
 script_end_attributes();

 script_summary(english: "Check for patch 146364-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146364-01", obsoleted_by:"119758-20 ", package:"SUNWsmbaS", version:"11.10.0,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146364-01", obsoleted_by:"119758-20 ", package:"SUNWsmbar", version:"11.10.0,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146364-01", obsoleted_by:"119758-20 ", package:"SUNWsmbau", version:"11.10.0,REV=2005.01.08.01.09");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
