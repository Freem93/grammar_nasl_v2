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
 script_id(37809);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 8 (sparc) : 111299-04");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 111299-04");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8: PPP patch.
Date this patch was last updated by Sun : Sep/06/02');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/111299-04");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_end_attributes();

 script_summary(english: "Check for patch 111299-04");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWapppr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWapppu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWarc", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWcsxu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWmdb", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWmdbx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWpppd", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWpppdr", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWpppdu", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWpppdx", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111299-04", obsoleted_by:"128624-01 108993-18 ", package:"SUNWpppgS", version:"11.8.0,REV=2001.02.21.14.02");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
