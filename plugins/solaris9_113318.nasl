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
 script_id(25397);
 script_version("$Revision: 1.23 $");

 script_name(english: "Solaris 9 (sparc) : 113318-35");
 script_osvdb_id(34908, 36596, 37324, 52554);
 script_cve_id("CVE-2007-2442", "CVE-2007-2882", "CVE-2007-3999", "CVE-2009-0319");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 113318-35");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9: NFS & autofs patch.
Date this patch was last updated by Sun : Mar/09/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/113318-35");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(119,20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/04");
 script_cvs_date("$Date: 2013/03/30 02:34:44 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/09/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/24");
 script_end_attributes();

 script_summary(english: "Check for patch 113318-35");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWatfsr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWatfsu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWcarx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWcarx", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWnfscr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWnfscu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWnfscx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWnfssr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWnfssu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWnfssx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWrsg", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWrsgk", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113318-35", obsoleted_by:"122300-41 ", package:"SUNWrsgx", version:"11.9.0,REV=2002.04.06.15.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
