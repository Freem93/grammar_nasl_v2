#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(33020);
 script_version ("$Revision: 1.3 $");
 name["english"] = "AIX 530007 : U817626";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing AIX PTF U817626 which is related
to the security of the package devices.pci.ad100501.rte

You should install this PTF for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"Run 'suma -x -a RqType=Security' on the remote system" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/04");
script_end_attributes();

 
 summary["english"] = "Check for PTF U817626"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2010 Tenable Network Security, Inc.");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

if ( aix_check_patch(ml:"530007", patch:"U817626", package:"devices.pci.ad100501.rte.5.3.7.1") < 0 ) 
  security_hole(port:0, extra:aix_report_get());
