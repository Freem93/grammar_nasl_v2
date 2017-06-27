# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/11/20.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(56678);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 10 (x86) : 146577-01 (deprecated)");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 146577-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: psp spheredesigner patch.
Date this patch was last updated by Sun : Oct/26/11');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/146577-01");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "patch_publication_date", value: "2011/10/26");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/31");
  script_cvs_date("$Date: 2012/11/20 11:44:56 $");
 script_end_attributes();

 script_summary(english: "Check for patch 146577-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146577-01", obsoleted_by:"122213-46 ", package:"SUNWgnome-img-editor", version:"2.6.0,REV=10.0.3.2004.12.16.18.25");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
