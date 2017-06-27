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
 script_id(35197);
 script_version("$Revision: 1.13 $");

 script_name(english: "Solaris 10 (sparc) : 138371-06");
 script_osvdb_id(54343, 54344);
 script_cve_id("CVE-2009-0360", "CVE-2009-0361");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 138371-06");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: mech_krb5.so.1 patch.
Date this patch was last updated by Sun : Mar/24/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1020129.1.html");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/17");
 script_cvs_date("$Date: 2011/10/24 20:59:24 $");
 script_end_attributes();

 script_summary(english: "Check for patch 138371-06");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWgssk", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWkrbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138371-06", obsoleted_by:"140074-05 143561-05 141500-03 ", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
