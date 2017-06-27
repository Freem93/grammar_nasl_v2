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
 script_id(23763);
 script_version ("$Revision: 1.18 $");
 name["english"] = "Solaris 10 (i386) : 117550-12";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 117550-12
(Sun Studio 9_x86: patch for Sun C++ 5.6_x86 C++ Compiler).

Date this patch was last updated by Sun : Wed Nov 26 05:16:44 MST 2008

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/117550-12" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/04");
 script_end_attributes();

 
 summary["english"] = "Check for patch 117550-12"; 
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROcpl", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROgc", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROlgc", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROscl", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROstl4a", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROstl4h", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROstl4o", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROtlbn7", version:"9.0,REV=2004.07.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"117550-12", obsoleted_by:"", package:"SPROtll7", version:"9.0,REV=2004.07.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
