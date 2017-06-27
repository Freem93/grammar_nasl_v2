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
 script_id(37070);
 script_version("$Revision: 1.5 $");

 script_name(english: "Solaris 5.10 (x86) : 125407-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125407-01");
 script_set_attribute(attribute: "description", value:
'Webservices, SunOS 5.9 5.10 5.9_x86 5.10_x86: patch.
Date this patch was last updated by Sun : Sep/05/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/125407-01");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2007/09/05");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_cvs_date("$Date: 2011/09/18 00:54:23 $");
 script_end_attributes();

 script_summary(english: "Check for patch 125407-01");
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125407-01", obsoleted_by:"", package:"SUNWjaxb2", version:"2.0.3,REV=2006.11.15.05.22");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125407-01", obsoleted_by:"", package:"SUNWjaxws", version:"2.0,REV=2006.11.15.05.22");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125407-01", obsoleted_by:"", package:"SUNWxwss", version:"2.0,REV=2006.09.28.03.41");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
