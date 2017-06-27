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
 script_id(38757);
 script_version("$Revision: 1.14 $");

 script_name(english: "Solaris 10 (x86) : 140119-11");
 script_osvdb_id(52864);
 script_cve_id("CVE-2009-0590");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 140119-11");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: sshd patch.
Date this patch was last updated by Sun : Aug/14/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/140119-11");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/13");
 script_cvs_date("$Date: 2012/06/14 20:11:56 $");
 script_end_attributes();

 script_summary(english: "Check for patch 140119-11");
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWopenssl-commands", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWopenssl-include", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWsshdr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"140119-11", obsoleted_by:"141525-05 142910-17 ", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
