# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/12/27.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(25544);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 5.9 (sparc) : 125276-08");
 script_osvdb_id(52513, 52581, 52582, 52583, 52584, 52585, 52586, 52587, 52588);
 script_cve_id("CVE-2009-0609");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125276-08");
 script_set_attribute(attribute: "description", value:
'Directory Server Enterprise Edition 6.3.1 : SunOS 5.9/5.10 Sparc N.
Date this patch was last updated by Sun : Feb/09/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/125276-08");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cwe_id(20);
 script_set_attribute(attribute: "patch_publication_date", value: "2009/02/09");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/18");
 script_cvs_date("$Date: 2011/12/27 15:44:24 $");
 script_end_attributes();

 script_summary(english: "Check for patch 125276-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-console-agent", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-console-cli", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-console-common", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-console-gui-help", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-console-gui", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-directory-client", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-directory-config", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-directory-dev", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-directory-ha", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-directory-man", version:"6.0,REV=2006.11.06.18.13");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-directory", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-proxy-client", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-proxy-config", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-proxy-man", version:"6.0,REV=2006.11.06.18.13");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-proxy", version:"6.0,REV=2007.01.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125276-08", obsoleted_by:"", package:"SUNWldap-shared", version:"6.0,REV=2007.01.25");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
