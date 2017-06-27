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
 script_id(39415);
 script_version("$Revision: 1.15 $");

 script_name(english: "Solaris 10 (sparc) : 141414-10");
 script_osvdb_id(57823);
 script_cve_id("CVE-2009-3164");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141414-10");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: kernel patch.
Date this patch was last updated by Sun : Sep/01/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1020829.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/16");
 script_cvs_date("$Date: 2011/10/24 20:59:24 $");
 script_end_attributes();

 script_summary(english: "Check for patch 141414-10");
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

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWiscsitgtu", version:"11.10.0,REV=2007.06.20.13.33");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWs9brandr", version:"11.10.0,REV=2008.04.24.03.37");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141414-10", obsoleted_by:"141444-09 ", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
