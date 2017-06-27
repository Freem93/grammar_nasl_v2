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
 script_id(13086);
 script_version("$Revision: 1.32 $");

 script_name(english: "Solaris 7 (sparc) : 106541-44");
 script_cve_id("CVE-2004-0790", "CVE-2004-0791");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 106541-44");
 script_set_attribute(attribute: "description", value:
'SunOS 5.7: Kernel Update Patch.
Date this patch was last updated by Sun : Dec/06/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1001318.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("$Date: 2011/10/24 20:59:24 $");
 script_end_attributes();

 script_summary(english: "Check for patch 106541-44");
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

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"FJSVhea", version:"1.0,REV=1998.11.16.20.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWarc", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWarcx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWatfsr", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcar", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcar", version:"11.7.0,REV=1999.01.11.15.30");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcarx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcarx", version:"11.7.0,REV=1998.11.30.15.02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcpr", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcpr", version:"11.7.0,REV=1998.11.16.20.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcprx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcprx", version:"11.7.0,REV=1998.11.16.20.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcsl", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcslx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcsr", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcsu", version:"11.7.0,REV=1998.10.06.00.59");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcsxu", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcvc", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWcvcx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWdpl", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWdplx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWdrr", version:"11.7.0,REV=1999.03.09.04.51");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWdrrx", version:"11.7.0,REV=1999.03.09.04.51");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWesu", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWesxu", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWhea", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWipc", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWkvm", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWkvm", version:"11.7.0,REV=1999.01.11.15.30");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWkvmx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWkvmx", version:"11.7.0,REV=1998.11.16.20.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWnisu", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWpcmci", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWpcmcu", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWpcmcx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWscpu", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWscpux", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWssad", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWssadx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWsxr", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWtnfc", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWtnfcx", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWtoo", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWtoox", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWvolr", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWvolu", version:"11.7.0,REV=1998.09.01.04.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-44", obsoleted_by:"", package:"SUNWypu", version:"11.7.0,REV=1998.09.01.04.16");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
