#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(52772);
 script_version ("$Revision: 1.1 $");
 
 script_name(english: "AIX 610005 : U837433");
 
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing a vendor supplied security patch");
 script_set_attribute(attribute: "description", value:
"The remote host is missing AIX PTF U837433 which is related
to the security of the package bos.rte.tty.6.1

You should install this PTF for your system to be up-to-date.");
 script_set_attribute(attribute: "solution", value: 
"Run 'suma -x -a RqType=Security' on the remote system");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_cvs_date("$Date: 2011/03/24 11:09:10 $");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/24");
 script_end_attributes();
 
 script_summary(english: "Check for PTF U837433");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english: "AIX Local Security Checks");
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");
if ( ! get_kb_item("Host/AIX/lslpp") ) exit(1, "No patch information");


if ( aix_check_patch(ml:"610005", patch:"U837433", package:"bos.rte.tty.6.1.5.3") < 0 ) 
  security_hole(port:0, extra:aix_report_get());
else exit(0, "Host is not vulnerable");
