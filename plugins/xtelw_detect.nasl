#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
  script_id(11120);
  script_version ("$Revision: 1.16 $");
  script_osvdb_id(2104);
  script_cvs_date("$Date: 2014/05/09 18:59:10 $");

 
  script_name(english:"xtelw Detection");
  script_summary(english:"Detect xteld in HyperTerminal mode");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a terminal emulation service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running xteld, a Minitel emulator, in HyperTerminal mode. 
This service allows users to connect to the Teletel network. 
Some of the servers are expensive. Note that by default, xteld forbids
access to the most expensive services." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/09/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/unknown", 1314);

  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");

# Quick way
port=1314;
# Slow way
#port = get_kb_item("Services/unknown"); 
#if (! port) { port=1314; }

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

banner = get_unknown_banner(port: port, dontfetch:0);
if (! banner) exit(0);

# I'm too lazy to parse the service list :-)
if (("Service Minitel" >< banner) && ("Xteld" >< banner))
{
 security_note(port);
 register_service(port: port, proto: "xtelw");
}


