# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(36967);
 script_version("$Revision: 1.8 $");

 script_name(english: "Solaris 5.9 (sparc) : 119796-04");
 script_cve_id("CVE-2007-0956");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119796-04");
 script_set_attribute(attribute: "description", value:
'SEAM 1.0.2_x86: patch for Solaris 9_x86.
Date this patch was last updated by Sun : Apr/03/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/119796-04");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_cvs_date("$Date: 2013/03/30 02:34:44 $");
 script_end_attributes();

 script_summary(english: "Check for patch 119796-04");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"i386", patch:"119796-04", obsoleted_by:"", package:"SUNWkr5sv", version:"5.9.0,REV=2003.09.30.23.07");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
