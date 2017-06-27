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
 script_id(50538);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2011/10/12 10:39:55 $");

 script_name(english:"Solaris 10 (x86) : 144489-17");
 script_summary(english:"Check for patch 144489-17");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing Sun Security Patch number 144489-17");
 script_set_attribute(attribute:"description", value:
'SunOS 5.10_x86: kernel patch.
Date this patch was last updated by Sun : Jun/17/11');
 script_set_attribute(attribute:"solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute:"see_also", value:
"https://getupdates.oracle.com/readme/144489-17");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/06/17");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWintgige", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWlxr", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWmrsas", version:"11.10.0,REV=2009.06.21.23.22");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWofk", version:"11.10.0,REV=2010.07.14.14.54");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWrdsv3", version:"11.10.0,REV=2010.07.14.14.54");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWrdsv3u", version:"11.10.0,REV=2010.07.14.14.54");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWrpcib", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144489-17", obsoleted_by:"144501-19 ", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
