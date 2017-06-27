# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2013/07/24.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(64552);
 script_version("$Revision: 1.4 $");

 script_name(english: "Solaris 10 (x86) : 148082-02");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 148082-02");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: ibmf, hermon patch.
Date this patch was last updated by Sun : Feb/07/13');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/148082-02");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "patch_publication_date", value: "2013/02/07");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/11");
  script_cvs_date("$Date: 2013/07/24 11:06:46 $");
 script_end_attributes();

 script_summary(english: "Check for patch 148082-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148082-02", obsoleted_by:"148416-02 148889-04 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148082-02", obsoleted_by:"148416-02 148889-04 ", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148082-02", obsoleted_by:"148416-02 148889-04 ", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148082-02", obsoleted_by:"148416-02 148889-04 ", package:"SUNWofk", version:"11.10.0,REV=2010.07.14.14.54");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148082-02", obsoleted_by:"148416-02 148889-04 ", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148082-02", obsoleted_by:"148416-02 148889-04 ", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
