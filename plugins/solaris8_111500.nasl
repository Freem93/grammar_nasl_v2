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
 script_id(23331);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 5.8 (sparc) : 111500-09");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 111500-09");
 script_set_attribute(attribute: "description", value:
'RSC 2.2 bug fixes.
Date this patch was last updated by Sun : Oct/29/02');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/111500-09");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2002/10/29");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:18 $");
 script_end_attributes();

 script_summary(english: "Check for patch 111500-09");
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

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWcrsc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWcrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWcrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWdersc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWdrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWdrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWerscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWerscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWesrsc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWfrrsc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWfrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWfrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWhrsc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWhrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWhrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWirscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWirscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWitrsc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWjersc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWjrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWjrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWkrsc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWkrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWkrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWrsc", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWsrscd", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWsrscj", version:"2.2,REV=2001.08.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111500-09", obsoleted_by:"", package:"SUNWsvrsc", version:"2.2,REV=2001.08.13");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
