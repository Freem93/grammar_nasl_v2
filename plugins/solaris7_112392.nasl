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
 script_id(24970);
 script_version("$Revision: 1.8 $");

 script_name(english: "Solaris 5.7 (sparc) : 112392-08");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 112392-08");
 script_set_attribute(attribute: "description", value:
'VxVM 3.5: Maintenance Patch for Volume Manager 3.5.
Date this patch was last updated by Sun : Aug/25/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/112392-08");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2005/08/25");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/05");
 script_cvs_date("$Date: 2011/09/18 01:29:17 $");
 script_end_attributes();

 script_summary(english: "Check for patch 112392-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"112392-08", obsoleted_by:"", package:"VRTSvmfrc", version:"3.5,REV=11.27.2002.12.35");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"112392-08", obsoleted_by:"", package:"VRTSvmfrm", version:"3.5,REV=11.27.2002.12.35");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"112392-08", obsoleted_by:"", package:"VRTSvmjac", version:"3.5,REV=11.27.2002.12.35");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"112392-08", obsoleted_by:"", package:"VRTSvmjam", version:"3.5,REV=11.27.2002.12.35");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"112392-08", obsoleted_by:"", package:"VRTSvmzhc", version:"3.5,REV=11.27.2002.12.35");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"112392-08", obsoleted_by:"", package:"VRTSvmzhm", version:"3.5,REV=11.27.2002.12.35");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"112392-08", obsoleted_by:"", package:"VRTSvxvm", version:"3.5,REV=06.21.2002.23.14");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
