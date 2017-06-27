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
 script_id(23272);
 script_version ("$Revision: 1.10 $");
 name["english"] = "Solaris 7 (i386) : 105188-18";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 105188-18
(SunLink X25 9.1 patch_x86).

Date this patch was last updated by Sun : Tue Jan 13 02:00:53 MST 2004

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/105188-18" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_end_attributes();

 
 summary["english"] = "Check for patch 105188-18"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWexpx", version:"9.1,PATCH=18");
e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWllc2a", version:"9.1,PATCH=18");
e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWx25a", version:"9.1,PATCH=18");
e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWx25b", version:"9.1,PATCH=18");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
