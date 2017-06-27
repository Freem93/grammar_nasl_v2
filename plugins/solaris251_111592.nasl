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
 script_id(23056);
 script_version ("$Revision: 1.10 $");
 name["english"] = "Solaris 2.5.1 (sparc) : 111592-01";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 111592-01
(Solstice Enterprise Agent 1.0.3: SNMP.).

Date this patch was last updated by Sun : Mon Feb 25 01:27:59 MST 2002

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/111592-01" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_end_attributes();

 
 summary["english"] = "Check for patch 111592-01"; 
 script_summary(english:summary["english"]);
 
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

e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"111592-01", obsoleted_by:"", package:"SUNWmibii", version:"1.3,REV=1998.09.08.15.08");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"111592-01", obsoleted_by:"", package:"SUNWsacom", version:"1.3,REV=1998.09.08.15.08");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"111592-01", obsoleted_by:"", package:"SUNWsadmi", version:"1.3,REV=1998.09.08.15.08");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"111592-01", obsoleted_by:"", package:"SUNWsasnm", version:"1.3,REV=1998.09.08.15.08");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
