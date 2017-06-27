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
 script_id(23149);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(5384);
 name["english"] = "Solaris 2.6 (sparc) : 110532-01";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 110532-01
(AnswerBook 1.4.3: HTTP GET overflow allows code execution).

Date this patch was last updated by Sun : Wed Nov 23 04:35:09 MST 2005

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/110532-01" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cvs_date("$Date: 2011/09/18 01:06:49 $");
 script_end_attributes();

 
 summary["english"] = "Check for patch 110532-01"; 
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

e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"110532-01", obsoleted_by:"", package:"SUNWab2u", version:"3.0,REV=2000.0804");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
else 
{
	set_kb_item(name:"BID-5384", value:TRUE);
}
