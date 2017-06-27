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
 script_id(23274);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(10594, 5986, 7820, 8079, 8314, 8831, 8929, 9477, 9962);
 name["english"] = "Solaris 7 (i386) : 106541-42";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing Sun Security Patch number 106541-42" );
 script_set_attribute(attribute:"description", value:
"SunOS 5.7_x86: tr dumps core with locale de and KJP 106541-07 or newer.

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/106541-42" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:17 $");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_end_attributes();

 
 summary["english"] = "Check for patch 106541-42"; 
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

e =  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"106541-42", obsoleted_by:"", package:"FJSVhea SUNWarc SUNWarcx SUNWatfsr SUNWcar.c SUNWcar.d SUNWcar.m SUNWcar.u SUNWcar.us SUNWcarx.u SUNWcarx.us SUNWcpr.m SUNWcpr.u SUNWcpr.us SUNWcprx.u SUNWcprx.us SUNWcsl SUNWcslx SUNWcsr SUNWcsu SUNWcsxu SUNWcvc.u SUNWcvcx.u SUNWdpl SUNWdplx SUNWdrr.u SUNWdrrx.u SUNWesu SUNWesxu SUNWhea SUNWipc SUNWkvm.c SUNWkvm.d SUNWkvm.m SUNWkvm.u SUNWkvm.us SUNWkvmx.u SUNWkvmx.us SUNWnisu SUNWpcmci SUNWpcmcu SUNWpcmcx SUNWscpu SUNWscpux SUNWssad SUNWssadx SUNWsxr.m SUNWtnfc SUNWtnfcx SUNWtoo SUNWtoox SUNWvolr SUNWvolu SUNWypu");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10594", value:TRUE);
	set_kb_item(name:"BID-5986", value:TRUE);
	set_kb_item(name:"BID-7820", value:TRUE);
	set_kb_item(name:"BID-8079", value:TRUE);
	set_kb_item(name:"BID-8314", value:TRUE);
	set_kb_item(name:"BID-8831", value:TRUE);
	set_kb_item(name:"BID-8929", value:TRUE);
	set_kb_item(name:"BID-9477", value:TRUE);
	set_kb_item(name:"BID-9962", value:TRUE);
}
