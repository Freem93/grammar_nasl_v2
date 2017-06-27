#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(49450);
 script_version ("$Revision: 1.1 $");
 name["english"] = "AIX 530011 : U837653";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing a vendor supplied security patch");
 script_set_attribute(attribute: "description", value:
"The remote host is missing AIX PTF U837653 which is related
to the security of the package devices.vdevice.hvterm1.rte

You should install this PTF for your system to be up-to-date.");
 script_set_attribute(attribute: "solution", value: 
"Run 'suma -x -a RqType=Security' on the remote system");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");
 script_cvs_date("$Date: 2010/09/22 11:40:00 $");
 script_end_attributes();
 
 summary["english"] = "Check for PTF U837653"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2010 Tenable Network Security, Inc.");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");
if ( ! get_kb_item("Host/AIX/lslpp") ) exit(1, "No patch information");


if ( aix_check_patch(ml:"530011", patch:"U837653", package:"devices.vdevice.hvterm1.rte.5.3.11.1") < 0 ) 
  security_hole(port:0, extra:aix_report_get());
else exit(0, "Host is not vulnerable");
