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
 script_id(23190);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 5.6 (x86) : 106872-18");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 106872-18");
 script_set_attribute(attribute: "description", value:
'Solstice Enterprise Agent 1.0.3: SNMP..
Date this patch was last updated by Sun : May/31/02');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/106872-18");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2002/05/31");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:16 $");
 script_end_attributes();

 script_summary(english: "Check for patch 106872-18");
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

e +=  solaris_check_patch(release:"5.6_x86", arch:"i386", patch:"106872-18", obsoleted_by:"", package:"SUNWmibii", version:"1.3,REV=1998.09.08.16.12");
e +=  solaris_check_patch(release:"5.6_x86", arch:"i386", patch:"106872-18", obsoleted_by:"", package:"SUNWsacom", version:"1.3,REV=1998.09.08.16.12");
e +=  solaris_check_patch(release:"5.6_x86", arch:"i386", patch:"106872-18", obsoleted_by:"", package:"SUNWsadmi", version:"1.3,REV=1998.09.08.16.12");
e +=  solaris_check_patch(release:"5.6_x86", arch:"i386", patch:"106872-18", obsoleted_by:"", package:"SUNWsasnm", version:"1.3,REV=1998.09.08.16.12");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
