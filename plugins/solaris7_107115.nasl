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
 script_id(13100);
 script_version("$Revision: 1.26 $");

 script_name(english: "Solaris 7 (sparc) : 107115-20");
 script_osvdb_id(17345, 18650);
 script_cve_id("CVE-2005-2032", "CVE-2005-4797");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 107115-20");
 script_set_attribute(attribute: "description", value:
'SunOS 5.7: lp Patch.
Date this patch was last updated by Sun : Mar/22/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/107115-20");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("$Date: 2011/09/18 01:29:16 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/15");
 script_end_attributes();

 script_summary(english: "Check for patch 107115-20");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107115-20", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107115-20", obsoleted_by:"", package:"SUNWpsf", version:"13.1,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107115-20", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107115-20", obsoleted_by:"", package:"SUNWscplp", version:"13.1,REV=1998.09.01.04.16");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
