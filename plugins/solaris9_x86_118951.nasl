# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(36445);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 5.9 (x86) : 118951-38");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 118951-38");
 script_set_attribute(attribute: "description", value:
'Portal Server 6.3.1_x86: Miscellaneous Fixes.
Date this patch was last updated by Sun : Apr/10/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/118951-38");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_end_attributes();

 script_summary(english: "Check for patch 118951-38");
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

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWiimps", version:"6.2,REV=2003.11.17.12.58");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWps", version:"6.2,REV=2003.11.17.12.53");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsap", version:"6.2,REV=2003.11.17.12.57");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsc", version:"6.2,REV=2003.11.17.12.33");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpscfg", version:"6.2,REV=2003.11.17.13.08");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpscp", version:"6.2,REV=2003.11.17.12.57");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsdt", version:"6.2,REV=2003.11.17.12.35");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsdtx", version:"6.2,REV=2003.11.17.12.53");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsgw", version:"6.2,REV=2003.11.17.13.00");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsgws", version:"6.2,REV=2003.11.17.13.01");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsks", version:"6.2,REV=2003.11.17.12.59");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsma", version:"6.3,REV=2004.05.07.19.22");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsmas", version:"6.3,REV=2004.05.07.19.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsmp", version:"6.2,REV=2003.11.17.12.56");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsnf", version:"6.2,REV=2003.11.17.13.07");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsnl", version:"6.2,REV=2003.11.17.13.03");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsnlp", version:"6.2,REV=2003.11.17.13.03");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsnm", version:"6.2,REV=2003.11.17.12.53");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsp", version:"6.2,REV=2003.11.17.12.37");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsplt", version:"6.3,REV=2004.05.07.18.52");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsps", version:"6.2,REV=2003.11.17.12.37");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsrw", version:"6.2,REV=2003.11.17.12.32");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsrwp", version:"6.2,REV=2003.11.17.13.00");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpssdk", version:"6.2,REV=2003.11.17.12.53");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpsse", version:"6.2,REV=2003.11.17.12.48");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpssp", version:"6.2,REV=2003.11.17.12.55");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpssso", version:"6.2,REV=2003.11.17.12.56");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118951-38", obsoleted_by:"", package:"SUNWpswsrpconsumer", version:"6.3,REV=2004.05.07.18.29");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
