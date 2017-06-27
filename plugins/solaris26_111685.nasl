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
 script_id(23920);
 script_version ("$Revision: 1.11 $");
 name["english"] = "Solaris 2.6 (sparc) : 111685-24";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 111685-24
(C++ 5.3: Patch for Forte Developer 6 update 2 C++ compiler).

Date this patch was last updated by Sun : Fri Dec 08 02:30:53 MST 2006

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/111685-24" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/18");
 script_end_attributes();

 
 summary["english"] = "Check for patch 111685-24"; 
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

e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROcpl", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROcplx", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROgc", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROgcx", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROlgc", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROlgcx", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROscl", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROsclx", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROtl7x", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROtlbn7", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROtll7", version:"6.2");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"111685-24", obsoleted_by:"OBSOLETE", package:"SPROtll7x", version:"6.2");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
