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
 script_id(33205);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 10 (sparc) : 136892-01");
 script_osvdb_id(40811, 41211);
 script_cve_id("CVE-2008-0122");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 136892-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: libc.so.1.9 patch.
Date this patch was last updated by Sun : Jun/06/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/136892-01");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/18");
 script_cvs_date("$Date: 2011/09/18 00:54:21 $");
 script_end_attributes();

 script_summary(english: "Check for patch 136892-01");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"136892-01", obsoleted_by:"138387-01 144488-13 ", package:"SUNWbcp", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
