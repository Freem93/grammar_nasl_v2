#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35724);
 script_version ("$Revision: 1.7 $");
 
 script_name(english: "TeamSpeak Server Administration Detection");
 script_set_attribute(attribute: "synopsis", value: 
"A TeamSpeak Server Administration web server is running on this port.");
 script_set_attribute(attribute: "description", value: 
"TeamSpeak is a proprietary Voice over IP conferencing software. It
is mainly used by gamers.");

 script_set_attribute(attribute: "see_also", value: "http://en.wikipedia.org/wiki/Teamspeak");
 script_set_attribute(attribute: "see_also", value: "http://www.teamspeak.com/");
 script_set_attribute(attribute: "solution", value: 
"Make sure that use of this software is in agreement with your
organization's security policies.");
 script_set_attribute(attribute: "risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/20");
 script_cvs_date("$Date: 2011/03/15 18:34:12 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english: 'Identifies TeamSpeak Server Administration');
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 14543);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 14534);

page = http_get_cache(port: port, item: "/", exit_on_fail: 1);

if ( "<title>TeamSpeak Server-Administration </title>" >< page &&
     'Server: Indy/9.00.10' >< page && 
     '<input type="submit" value="Login">' >< page &&
     '<a href="slogin.html">SuperAdmin Login</a>' >< page) 
{
  security_note(port: port);
  set_kb_item(name: "www/teamspeak", value: TRUE);
}
