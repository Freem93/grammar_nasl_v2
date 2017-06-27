#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14619);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2014/03/12 15:37:15 $");
 script_cve_id("CVE-2003-0694");
 name["english"] = "AIX 5.1 : IY48658";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing AIX Critical Security Patch number IY48658
(Sendmail prescan() vulnerability).

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://www-912.ibm.com/eserver/support/fixes/" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sendmail SMTP Address prescan Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/01");
 script_end_attributes();

 
 summary["english"] = "Check for patch IY48658"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

 if( aix_check_patch(release:"5.1", patch:"IY48658", package:"bos.net.tcp.client.5.1.0.59") < 0 ) 
   security_hole();
