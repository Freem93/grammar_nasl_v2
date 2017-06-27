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
 script_id(39532);
 script_version("$Revision: 1.8 $");

 script_name(english: "Solaris 10 (sparc) : 141778-02");
 script_osvdb_id(55329);
 script_cve_id("CVE-2009-2282");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141778-02");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: vntsd patch.
Date this patch was last updated by Sun : Jun/25/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/141778-02");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/26");
 script_cvs_date("$Date: 2011/09/18 00:54:22 $");
 script_end_attributes();

 script_summary(english: "Check for patch 141778-02");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc.sun4v", patch:"141778-02", obsoleted_by:"141514-02 ", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc.sun4v", patch:"141778-02", obsoleted_by:"141514-02 ", package:"SUNWkvm", version:"11.10.0,REV=2005.08.04.12.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc.sun4v", patch:"141778-02", obsoleted_by:"141514-02 ", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc.sun4v", patch:"141778-02", obsoleted_by:"141514-02 ", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");