# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(22971);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Solaris 10 (sparc) : 122476-01";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 122476-01
(Patch-ID# 122476-01).

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/122476-01" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_end_attributes();

 
 summary["english"] = "Check for patch 122476-01"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e =  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122476-01", obsoleted_by:"", package:"AIX HPUX Linux SunOS SunOS_x86 WINNT");

if ( e < 0 ) security_hole(0);
