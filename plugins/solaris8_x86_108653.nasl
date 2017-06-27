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
 script_id(23429);
 script_version("$Revision: 1.21 $");

 script_name(english: "Solaris 8 (x86) : 108653-87");
 script_osvdb_id(19699, 19700);
 script_cve_id("CVE-2005-3099");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 108653-87");
 script_set_attribute(attribute: "description", value:
'X11 6.4.1_x86: Xsun patch.
Date this patch was last updated by Sun : May/26/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/108653-87");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:19 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/26");
 script_end_attributes();

 script_summary(english: "Check for patch 108653-87");
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

e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwacx", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwdxm", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwfa", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwfnt", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwice", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwinc", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwman", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwplt", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwpmn", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108653-87", obsoleted_by:"119068-01 ", package:"SUNWxwslb", version:"6.4.1.3800,REV=0.1999.12.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
