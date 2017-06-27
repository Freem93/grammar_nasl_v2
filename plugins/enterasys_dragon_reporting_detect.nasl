#
# (C) Tenable Network Security, Inc.
#

# Changes by Tenable:
# - Changed family (8/31/09)
# - rewritten (2009-11-17)

include("compat.inc");

if(description)
{
 script_id(18532);
 script_version("$Revision: 2.5 $");
 
 script_name(english:"Enterasys Dragon Enterprise Reporting Detection");

 script_set_attribute(attribute:"synopsis", value:
"Dragon Reporting is running on this port." );
 script_set_attribute(attribute:"description", value:
"The reporting console for Dragon, a network intrusion detection system 
distributed by Enterasys, is running on this port." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/20");
 script_cvs_date("$Date: 2011/03/15 18:34:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for Enterasys Dragon Enterprise Reporting console");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 9443);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 9443);

page = http_get_cache(port: port, item: "/", exit_on_fail: 1);

if ( egrep(string: page, 
       pattern: "<title>Dragon (Enterprise )?Reporting</title>") && 
     egrep(string: page, 
     	pattern: "Copyright &copy; 1999-20[01][0-9] Enterasys Networks, Inc"))
  security_note(port);

	  