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
 script_id(38781);
 script_version("$Revision: 1.9 $");

 script_name(english: "Solaris 10 (sparc) : 140074-09");
 script_osvdb_id(54979);
 script_cve_id("CVE-2009-1933");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 140074-09");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: pam_krb5.so.1 patch.
Date this patch was last updated by Sun : Aug/17/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/140074-09");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
 script_cwe_id(255);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/15");
 script_cvs_date("$Date: 2011/09/18 00:54:22 $");
 script_end_attributes();

 script_summary(english: "Check for patch 140074-09");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWgss", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWgssc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWgssk", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWkrbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"140074-09", obsoleted_by:"143561-05 141500-03 ", package:"SUNWspnego", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
