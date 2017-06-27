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
 script_id(43884);
 script_version("$Revision: 1.7 $");

 script_name(english: "Solaris 10 (sparc) : 120036-07");
 script_osvdb_id(36594);
 script_cve_id("CVE-2007-3458");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120036-07");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: libldap patch.
Date this patch was last updated by Sun : Aug/31/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000456.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/01/14");
 script_cvs_date("$Date: 2011/10/24 20:59:24 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/26");
 script_end_attributes();

 script_summary(english: "Check for patch 120036-07");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120036-07", obsoleted_by:"118833-36 ", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120036-07", obsoleted_by:"118833-36 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
