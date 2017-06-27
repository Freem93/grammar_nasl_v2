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
 script_id(31187);
 script_version("$Revision: 1.12 $");

 script_name(english: "Solaris 10 (sparc) : 136716-01");
 script_osvdb_id(47420);
 script_cve_id("CVE-2008-3450");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 136716-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: namefs driver.
Date this patch was last updated by Sun : Jan/24/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1019268.1.html");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/26");
 script_cvs_date("$Date: 2011/10/24 20:59:24 $");
 script_end_attributes();

 script_summary(english: "Check for patch 136716-01");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"136716-01", obsoleted_by:"137032-01 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
