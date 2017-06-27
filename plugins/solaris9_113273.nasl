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
 script_id(13532);
 script_version("$Revision: 1.52 $");

 script_name(english: "Solaris 9 (sparc) : 113273-16");
 script_osvdb_id(29152);
 script_cve_id("CVE-2006-4924");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 113273-16");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9: /usr/lib/ssh/sshd patch.
Date this patch was last updated by Sun : Oct/19/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/113273-16");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("$Date: 2011/09/18 01:40:36 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/25");
 script_end_attributes();

 script_summary(english: "Check for patch 113273-16");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113273-16", obsoleted_by:"122300-17 ", package:"SUNWsshcu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113273-16", obsoleted_by:"122300-17 ", package:"SUNWsshdr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113273-16", obsoleted_by:"122300-17 ", package:"SUNWsshdu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113273-16", obsoleted_by:"122300-17 ", package:"SUNWsshr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113273-16", obsoleted_by:"122300-17 ", package:"SUNWsshu", version:"11.9.0,REV=2002.04.06.15.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
