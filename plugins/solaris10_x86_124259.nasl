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
 script_id(25394);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 10 (x86) : 124259-06");
 script_osvdb_id(34908);
 script_cve_id("CVE-2007-2882");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 124259-06");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: ufs and nfs driver patch.
Date this patch was last updated by Sun : Jun/12/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/124259-06");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/04");
 script_cvs_date("$Date: 2011/09/18 00:54:23 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/24");
 script_end_attributes();

 script_summary(english: "Check for patch 124259-06");
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"124259-06", obsoleted_by:"120012-14 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"124259-06", obsoleted_by:"120012-14 ", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
