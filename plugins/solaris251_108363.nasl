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
 script_id(12739);
 script_version ("$Revision: 1.22 $");
 script_bugtraq_id(3517);
 name["english"] = "Solaris 2.5.1 (sparc) : 108363-02";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 108363-02
(CDE 1.0.2: libDtSvc Patch).

Date this patch was last updated by Sun : Tue Dec 04 04:58:34 MST 2001

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/108363-02" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Solaris dtspcd Heap Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cvs_date("$Date: 2011/09/18 01:06:46 $");
 script_end_attributes();

 
 summary["english"] = "Check for patch 108363-02"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"108363-02", obsoleted_by:"", package:"SUNWdtbas", version:"1.0.2,REV=10.96.04.12");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
else 
{
	set_kb_item(name:"BID-3517", value:TRUE);
}
