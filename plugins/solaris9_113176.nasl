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
 script_id(23487);
 script_version("$Revision: 1.12 $");

 script_name(english: "Solaris 5.9 (sparc) : 113176-03");
 script_cve_id("CVE-2002-2374");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 113176-03");
 script_set_attribute(attribute: "description", value:
'PatchPro patch engine corrections.
Date this patch was last updated by Sun : Dec/17/03');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/113176-03");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(59,362);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:40:36 $");
 script_end_attributes();

 script_summary(english: "Check for patch 113176-03");
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

e +=  solaris_check_patch(release:"5.9", arch:"sparc,i386", patch:"113176-03", obsoleted_by:"", package:"SUNWppmn", version:"2.1");
e +=  solaris_check_patch(release:"5.9", arch:"sparc,i386", patch:"113176-03", obsoleted_by:"", package:"SUNWppro", version:"2.1");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
