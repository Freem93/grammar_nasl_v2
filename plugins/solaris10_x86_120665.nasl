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
 script_id(19746);
 script_version("$Revision: 1.21 $");

 script_name(english: "Solaris 10 (x86) : 120665-01");
 script_osvdb_id(19510);
 script_cve_id("CVE-2005-3001");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120665-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: tl driver patch.
Date this patch was last updated by Sun : Sep/15/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000190.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/17");
 script_cvs_date("$Date: 2011/10/24 20:59:24 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/19");
 script_end_attributes();

 script_summary(english: "Check for patch 120665-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120665-01", obsoleted_by:"118855-15 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_note(0);
	else  
	   security_note(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
