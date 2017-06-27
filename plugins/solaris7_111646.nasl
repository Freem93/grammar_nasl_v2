# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/10/24.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13178);
 script_version("$Revision: 1.19 $");

 script_name(english: "Solaris 7 (sparc) : 111646-01");
 script_osvdb_id(18269);
 script_cve_id("CVE-2005-4795");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 111646-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.7: BCP libmle buffer overflow.
Date this patch was last updated by Sun : Aug/06/01');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000224.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("$Date: 2011/10/24 20:59:25 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/25");
 script_end_attributes();

 script_summary(english: "Check for patch 111646-01");
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

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"111646-01", obsoleted_by:"", package:"SUNWjbcp", version:"1.8,REV=1.0.45");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
