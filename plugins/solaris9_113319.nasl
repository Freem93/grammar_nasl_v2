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
 script_id(13535);
 script_version("$Revision: 1.32 $");

 script_name(english: "Solaris 9 (sparc) : 113319-27");
 script_osvdb_id(31576, 48454);
 script_cve_id("CVE-2007-0165", "CVE-2008-4619");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 113319-27");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9: libnsl, nispasswdd patch.
Date this patch was last updated by Sun : Jan/08/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000297.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("$Date: 2011/10/24 20:59:25 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/09");
 script_end_attributes();

 script_summary(english: "Check for patch 113319-27");
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

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWarc", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWarcx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWcsl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWcslx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWcstlx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113319-27", obsoleted_by:"115695-02 112960-48 ", package:"SUNWnisu", version:"11.9.0,REV=2002.04.06.15.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
