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
 script_id(20272);
 script_version("$Revision: 1.27 $");

 script_name(english: "Solaris 10 (sparc) : 121229-02");
 script_osvdb_id(19919, 28549, 29260, 29261, 29262, 29263);
 script_cve_id("CVE-2005-2969", "CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4339", "CVE-2006-4343", "CVE-2006-5201", "CVE-2006-7140", "CVE-2007-5135");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 121229-02");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: libssl patch.
Date this patch was last updated by Sun : Apr/23/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1001144.1.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/07");
 script_cvs_date("$Date: 2012/06/14 20:02:12 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/11");
 script_end_attributes();

 script_summary(english: "Check for patch 121229-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"121229-02", obsoleted_by:"120011-14 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"121229-02", obsoleted_by:"120011-14 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"121229-02", obsoleted_by:"120011-14 ", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"121229-02", obsoleted_by:"120011-14 ", package:"SUNWopenssl-include", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"121229-02", obsoleted_by:"120011-14 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
