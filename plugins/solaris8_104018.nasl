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
 script_id(23298);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(4089);
 name["english"] = "Solaris 8 (sparc) : 104018-11";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 104018-11
(Solstice Site/SunNet/Domain Manager 2.3 Rev B: jumbo patch).

Date this patch was last updated by Sun : Thu Jul 22 03:32:11 MDT 2004

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/104018-11" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:18 $");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_end_attributes();

 
 summary["english"] = "Check for patch 104018-11"; 
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

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWcccfg", version:"1.2");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWccrcv", version:"1.2");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWccsnd", version:"1.2");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWsnmag", version:"2.3");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWsnmct", version:"2.3");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWsnmpd", version:"2.3");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
else 
{
	set_kb_item(name:"BID-4089", value:TRUE);
}
