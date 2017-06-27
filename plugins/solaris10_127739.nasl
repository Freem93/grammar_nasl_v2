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
 script_id(29205);
 script_version("$Revision: 1.14 $");

 script_name(english: "Solaris 10 (sparc) : 127739-03");
 script_osvdb_id(40821);
 script_cve_id("CVE-2007-6180");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 127739-03");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: rpcmod patch.
Date this patch was last updated by Sun : Dec/07/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/127739-03");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:C/A:C");
 script_cwe_id(362);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/04");
 script_cvs_date("$Date: 2011/09/18 00:54:21 $");
 script_end_attributes();

 script_summary(english: "Check for patch 127739-03");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127739-03", obsoleted_by:"128294-02 137137-09 138070-02 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
