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
 script_id(27028);
 script_version("$Revision: 1.9 $");

 script_name(english: "Solaris 5.9 (x86) : 116649-23");
 script_cve_id("CVE-2009-1934");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 116649-23");
 script_set_attribute(attribute: "description", value:
'Web Server 6.1: Sun ONE Web Server 6.1_x86 Patch WS61SP11.
Date this patch was last updated by Sun : May/29/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/116649-23");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/12");
 script_cvs_date("$Date: 2011/09/18 01:40:37 $");
 script_end_attributes();

 script_summary(english: "Check for patch 116649-23");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"i386", patch:"116649-23", obsoleted_by:"", package:"SUNWwbsvr", version:"6.1,REV=2003.11.21.14.20");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
