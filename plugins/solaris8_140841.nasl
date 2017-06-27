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
 script_id(38774);
 script_version("$Revision: 1.6 $");

 script_name(english: "Solaris 8 (sparc) : 140841-01");
 script_osvdb_id(54979);
 script_cve_id("CVE-2009-1933");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 140841-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8: gssd patch.
Date this patch was last updated by Sun : May/13/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/140841-01");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
 script_cwe_id(255);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/14");
 script_cvs_date("$Date: 2011/09/18 01:29:19 $");
 script_end_attributes();

 script_summary(english: "Check for patch 140841-01");
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

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"140841-01", obsoleted_by:"", package:"SUNWgss", version:"11.8.0,REV=2000.01.08.18.12");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
