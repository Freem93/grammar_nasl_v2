#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3210 ) exit(0);



include("compat.inc");

if(description)
{
 script_id(33813);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2013/07/19 10:43:04 $");

 script_name(english: "Port scanner dependency");
 script_summary(english: "Used for the re-ordering of several scanners");
 
 script_set_attribute(attribute:"synopsis", value:
"Portscanners stub." );
 script_set_attribute(attribute:"description", value:
"This plugin is an internal dependency used by several Nessus scripts. 
It does not perform anything by itself." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/25");
 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();
 
 script_category(ACT_SETTINGS);	
 
 script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 script_dependencies("ping_host.nasl", "wmi_netstat.nbin", "netstat_portscan.nasl", "snmpwalk_portscan.nasl");
 if ( defined_func("resolv") ) script_dependencies("setup.nbin");
 exit(0);
}

exit(0);
