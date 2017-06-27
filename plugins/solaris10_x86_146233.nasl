# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2014/01/16.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(64250);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 10 (x86) : 146233-20");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 146233-20");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: iSCSI patch.
Date this patch was last updated by Sun : Oct/01/12');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/146233-20");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "patch_publication_date", value: "2012/10/01");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/27");
  script_cvs_date("$Date: 2014/01/16 12:03:00 $");
 script_end_attributes();

 script_summary(english: "Check for patch 146233-20");
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWcfcl", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWcfclr", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWfchba", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWfcip", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWfcmdb", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWfcp", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWfcsm", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWfctl", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWiscsir", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWiscsiu", version:"11.10.0,REV=2005.01.04.14.30");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146233-20", obsoleted_by:"147144-17 ", package:"SUNWmpathadmr", version:"11.10.0,REV=2006.06.15.16.38");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
