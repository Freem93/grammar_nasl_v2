#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if(description)
{
 script_id(33812);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2011/03/21 18:19:28 $");

 script_name(english: "Port scanners settings");
 
 script_set_attribute(attribute:"synopsis", value:
"Portscanners options." );
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous global variables for Nessus port
scanners. It does not perform any security check." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/25");
script_set_attribute(attribute:"plugin_type", value:"settings");
script_end_attributes();

 
 script_summary(english: "Sets KB entries for port scanners");
 script_category(ACT_INIT);	
 
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 script_add_preference(name: "Check open TCP ports found by local port enumerators", type:"checkbox", value:"no");
 if ( NASL_LEVEL >= 3210 )
  script_add_preference(name: "Only run network port scanners if local port enumeration failed", type:"checkbox", value:"yes");
 exit(0);
}

opt = script_get_preference("Check open TCP ports found by local port enumerators");
if (opt && opt == "yes")
 set_kb_item(name: "PortscannersSettings/probe_TCP_ports", value:TRUE);

if ( NASL_LEVEL >= 3210 ) 
{
opt = script_get_preference("Only run network port scanners if local port enumeration failed");
if (! opt || "yes" >< opt)
  set_kb_item(name: "PortscannersSettings/run_only_if_needed", value:TRUE);
}
