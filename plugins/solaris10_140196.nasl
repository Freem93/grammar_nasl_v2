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
 script_id(35568);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 10 (sparc) : 140196-01");
 script_osvdb_id(52540);
 script_xref(name:"IAVT", value:"2009-T-0008");
 script_cve_id("CVE-2009-0267");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 140196-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: libike.so.1 patch.
Date this patch was last updated by Sun : Jan/20/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1019843.1.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/02");
 script_cvs_date("$Date: 2012/06/14 19:22:24 $");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_summary(english: "Check for patch 140196-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140196-01", obsoleted_by:"139555-08 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
