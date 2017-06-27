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
 script_id(13213);
 script_version("$Revision: 1.20 $");

 script_name(english: "Solaris 7 (x86) : 107375-03");
 script_osvdb_id(18809);
 script_cve_id("CVE-2005-4796");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 107375-03");
 script_set_attribute(attribute: "description", value:
'Openwindows 3.6.1_x86: Xview Patch.
Date this patch was last updated by Sun : Aug/02/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1001316.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("$Date: 2011/10/24 20:59:25 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/09");
 script_end_attributes();

 script_summary(english: "Check for patch 107375-03");
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

e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"107375-03", obsoleted_by:"", package:"SUNWolinc", version:"3.6.1,REV=1.98.08.13");
e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"107375-03", obsoleted_by:"", package:"SUNWolrte", version:"3.6.1,REV=1.98.08.13");
e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"107375-03", obsoleted_by:"", package:"SUNWolslb", version:"3.6.1,REV=1.98.08.13");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_note(0);
	else  
	   security_note(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
