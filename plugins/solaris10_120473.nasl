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
 script_id(25069);
 script_version("$Revision: 1.28 $");

 script_name(english: "Solaris 10 (sparc) : 120473-12");
 script_osvdb_id(36595);
 script_cve_id("CVE-2007-2798");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120473-12");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: libc nss ldap PAM zfs patch.
Date this patch was last updated by Sun : Jul/11/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000466.1.html");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/19");
 script_cvs_date("$Date: 2011/10/24 20:59:24 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/26");
 script_end_attributes();

 script_summary(english: "Check for patch 120473-12");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWaudit", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWdmgtu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWkvm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWperl584usr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWpl5u", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWsra", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWtecla", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWvolu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120473-12", obsoleted_by:"120011-14 ", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
