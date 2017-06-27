#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14437);
 script_version ("$Revision: 1.12 $");
 name["english"] = "AIX 5.2 : IY55682";
 script_cve_id("CVE-2004-0544", "CVE-2004-0545");
 script_bugtraq_id(9905, 10230);
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing AIX Critical Security Patch number IY55682
(SECURITY: Possible buffer overflow in putlvcb command).

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://www-912.ibm.com/eserver/support/fixes/" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/27");
 script_cvs_date("$Date: 2016/11/11 19:58:28 $");
 script_end_attributes();

 
 summary["english"] = "Check for patch IY55682"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

 if( aix_check_patch(release:"5.2", patch:"IY55682", package:"bos.rte.lvm.5.2.0.31") < 0 ) 
   security_hole();
