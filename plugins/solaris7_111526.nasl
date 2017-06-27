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
 script_id(23242);
 script_version("$Revision: 1.12 $");

 script_name(english: "Solaris 5.7 (sparc) : 111526-16");
 script_cve_id("CVE-2004-2758");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 111526-16");
 script_set_attribute(attribute: "description", value:
'SunForum 3.2: fixes and enhancements.
Date this patch was last updated by Sun : Nov/30/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/111526-16");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute: "patch_publication_date", value: "2005/11/30");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:17 $");
 script_end_attributes();

 script_summary(english: "Check for patch 111526-16");
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

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNW5dat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWcdat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWdat", version:"3.2.0,REV=2001.05.02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWdatu", version:"3.2.0,REV=2001.04.24");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWdedat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWesdat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWfrdat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWhdat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWitdat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWjadat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWjpdat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWkeep", version:"1.0.0,REV=2001.04.24");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWkodat", version:"3.2.0,REV=2002.01.29");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWphone", version:"3.2.0,REV=2001.04.26");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111526-16", obsoleted_by:"", package:"SUNWsvdat", version:"3.2.0,REV=2002.01.29");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
