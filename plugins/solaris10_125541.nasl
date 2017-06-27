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
 script_id(29826);
 script_version("$Revision: 1.10 $");

 script_name(english: "Solaris 10 (sparc) : 125541-04");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125541-04");
 script_set_attribute(attribute: "description", value:
'Mozilla 1.7: Mozilla Thunderbird email client.
Date this patch was last updated by Sun : May/12/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/125541-04");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/02");
 script_end_attributes();

 script_summary(english: "Check for patch 125541-04");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"125541-04", obsoleted_by:"", package:"SUNWthunderbird", version:"2.0.0.4,REV=10.4.3.2007.06.22.22.21");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
