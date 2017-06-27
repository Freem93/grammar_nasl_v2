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
 script_id(25456);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 5.10 (sparc) : 119345-07");
 script_cve_id("CVE-2009-0688");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119345-07");
 script_set_attribute(attribute: "description", value:
'SASL 2.19.20090601: Simple Authentication and Security Layer.
Date this patch was last updated by Sun : Jul/21/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/119345-07");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/08");
 script_cvs_date("$Date: 2012/06/14 20:21:39 $");
 script_end_attributes();

 script_summary(english: "Check for patch 119345-07");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"119345-07", obsoleted_by:"", package:"SUNWsasl", version:"2.17,REV=2004.04.06.15.24");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
