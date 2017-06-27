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
 script_id(22996);
 script_version("$Revision: 1.17 $");

 script_name(english: "Solaris 5.10 (x86) : 120880-08");
 script_cve_id("CVE-2008-5422");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120880-08");
 script_set_attribute(attribute: "description", value:
'Sun Ray Core Services version 3.1 Patch Update SunOS 5.10_x86.
Date this patch was last updated by Sun : Nov/26/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/120880-08");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 00:54:22 $");
 script_end_attributes();

 script_summary(english: "Check for patch 120880-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWuta", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutesa", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutfw", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutgsm", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutkio", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutm", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWuto", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutps", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutr", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutsto", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutu", version:"3.1_32,REV=2005.08.24.08.55");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
