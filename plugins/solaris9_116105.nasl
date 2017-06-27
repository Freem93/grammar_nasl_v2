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
 script_id(23693);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 9 (sparc) : 116105-09");
 script_osvdb_id(36509);
 script_cve_id("CVE-2007-2754");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 116105-09");
 script_set_attribute(attribute: "description", value:
'X11 6.6.1: FreeType patch.
Date this patch was last updated by Sun : Aug/11/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/116105-09");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/20");
 script_cvs_date("$Date: 2011/09/18 01:40:36 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/22");
 script_end_attributes();

 script_summary(english: "Check for patch 116105-09");
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

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"116105-09", obsoleted_by:"", package:"SUNWfreetype2-64", version:"6.6.1.6400,REV=0.2003.01.10");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"116105-09", obsoleted_by:"", package:"SUNWfreetype2", version:"6.6.1.6400,REV=0.2003.01.10");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
