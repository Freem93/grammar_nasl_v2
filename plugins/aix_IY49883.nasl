#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14429);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2003-0914");
 name["english"] = "AIX 5.2 : IY49883";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing AIX Critical Security Patch number IY49883
(Anti-cache poison techniques to negative answers).

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://www-912.ibm.com/eserver/support/fixes/" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/27");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");
 script_end_attributes();

 
 summary["english"] = "Check for patch IY49883"; 
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

 if( aix_check_patch(release:"5.2", patch:"IY49883", package:"bos.net.tcp.server.5.2.0.16") < 0 ) 
   security_warning();
