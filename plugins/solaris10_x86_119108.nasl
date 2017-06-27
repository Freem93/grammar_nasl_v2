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
 script_id(19745);
 script_version("$Revision: 1.6 $");

 script_name(english: "Solaris 10 (x86) : 119108-06");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119108-06");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86, Sun Update Connection Clie.
Date this patch was last updated by Sun : Sep/15/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/119108-06");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/17");
 script_end_attributes();

 script_summary(english: "Check for patch 119108-06");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWbreg", version:"1.0");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWccccfg", version:"1.0.0");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWccccr", version:"001.000.000");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWccccrr", version:"001.000.000");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWccfw", version:"001.000.000");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWccfwctrl", version:"1.0.0");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWccinv", version:"1.0.0");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWccsign", version:"001.000.000");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWcctpx", version:"001.000.000");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWcsmauth", version:"0.1,REV=2005.05.12.11.43");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWdc", version:"1.0");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWppro-plugin-sunos-base", version:"5.0,REV=2005.01.09.21.19");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWppror", version:"5.0,REV=2005.01.09.21.19");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWpprou", version:"5.0,REV=2005.01.09.21.19");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWswupcl", version:"1.0.3,REV=2005.06.23.09.01");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWupdatemgrr", version:"0.1,REV=2005.05.20.11.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119108-06", obsoleted_by:"121454-02 ", package:"SUNWupdatemgru", version:"0.1,REV=2005.05.20.11.37");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
