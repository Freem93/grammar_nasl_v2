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
 script_id(21260);
 script_version("$Revision: 1.24 $");

 script_name(english: "Solaris 10 (sparc) : 122856-03");
 script_osvdb_id(24037, 26197);
 script_cve_id("CVE-2006-0058", "CVE-2006-1173");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 122856-03");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: sendmail patch.
Date this patch was last updated by Sun : Oct/17/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/122856-03");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/21");
 script_cvs_date("$Date: 2012/06/14 20:29:54 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/22");
 script_end_attributes();

 script_summary(english: "Check for patch 122856-03");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122856-03", obsoleted_by:"118833-36 ", package:"SUNWsndmr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122856-03", obsoleted_by:"118833-36 ", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
