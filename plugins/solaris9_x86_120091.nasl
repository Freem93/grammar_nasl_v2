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
 script_id(23615);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 5.9 (x86) : 120091-15");
 script_cve_id("CVE-2008-2945");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120091-15");
 script_set_attribute(attribute: "description", value:
'AM 6.2_x86: Sun Java System Access Manager.
Date this patch was last updated by Sun : Feb/05/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/120091-15");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:40:37 $");
 script_end_attributes();

 script_summary(english: "Check for patch 120091-15");
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

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamcon", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamconsdk", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamfcd", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamjwsdp", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWampwd", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamrsa", version:"6.2,REV=04.04.23.19.49");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamsam", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamsci", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamsdk", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamsdkconfig", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamsvc", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamsvcconfig", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120091-15", obsoleted_by:"", package:"SUNWamutl", version:"6.2,REV=04.04.23.19.50");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
