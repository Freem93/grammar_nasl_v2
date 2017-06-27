# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/10/12.

#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if (description)
{
 script_id(48918);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2011/10/12 10:39:55 $");

 script_name(english:"Solaris 10 (x86) : 138881-02");
 script_summary(english:"Check for patch 138881-02");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing Sun Security Patch number 138881-02");
 script_set_attribute(attribute:"description", value:
'SunOS 5.10_x86: ses patch.
Date this patch was last updated by Sun : Aug/27/10');
 script_set_attribute(attribute:"solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute:"see_also", value:
"https://getupdates.oracle.com/readme/138881-02");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/08/27");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/29");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english:"Solaris Local Security Checks");
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138881-02", obsoleted_by:"144501-19 ", package:"SUNWses", version:"11.10.0,REV=2006.03.15.01.46");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
