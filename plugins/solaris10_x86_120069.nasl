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
 script_id(24342);
 script_version("$Revision: 1.20 $");

 script_name(english: "Solaris 10 (x86) : 120069-03");
 script_osvdb_id(31881);
 script_xref(name:"IAVB", value:"2007-B-0006");
 script_cve_id("CVE-2007-0882");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120069-03");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: in.telnetd patch.
Date this patch was last updated by Sun : Feb/21/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/120069-03");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Sun Solaris Telnet Remote Authentication Bypass Vulnerability');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/14");
 script_cvs_date("$Date: 2012/08/18 02:33:45 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/02/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/10");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_summary(english: "Check for patch 120069-03");
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120069-03", obsoleted_by:"127128-11 125419-01 ", package:"SUNWtnetd", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
