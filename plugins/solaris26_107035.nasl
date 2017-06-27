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
 script_id(23124);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 5.6 (sparc) : 107035-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 107035-01");
 script_set_attribute(attribute: "description", value:
'Solstice Enterprise Agent 1.0.1: SNMP DMI.
Date this patch was last updated by Sun : Nov/16/98');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/107035-01");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "1998/11/16");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:06:48 $");
 script_end_attributes();

 script_summary(english: "Check for patch 107035-01");
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

e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"107035-01", obsoleted_by:"", package:"SUNWmibii", version:"1.1,REV=1997.07.15.21.46");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"107035-01", obsoleted_by:"", package:"SUNWsacom", version:"1.1,REV=1997.07.15.21.46");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"107035-01", obsoleted_by:"", package:"SUNWsadmi", version:"1.1,REV=1997.07.15.21.46");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"107035-01", obsoleted_by:"", package:"SUNWsasnm", version:"1.1,REV=1997.07.15.21.46");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
