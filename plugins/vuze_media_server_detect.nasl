#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(51060);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");

 script_name(english:"Vuze Media Server Detection");
 script_summary(english:"Vuze Media Server Detection");

 script_set_attribute(attribute:"synopsis", value:
"Vuze Media Server is running on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an instance of Vuze Media Server.  This
server is in the form of a plugin for Vuze, a BitTorrent client." );
 script_set_attribute(attribute:"solution", value:
"Make sure that the use of this program agrees with your
organization's acceptable use and security policies. 

Note that filtering traffic to or from this port is not a sufficient
solution since the software can use a random port.");
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www"); 
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item_or_exit("upnp/www");

ret = http_send_recv3(port:port, method:"HEAD",item:"/RootDevice.xml",exit_on_fail:TRUE);
header = ret[1];
match = eregmatch(string:header,pattern:'(^|\r\n)Server:[ \t]*Azureus[ \t]*([0-9].*)\r\n',icase:TRUE);
if(match)
{
    security_note(port);
    version = match[2];
    set_kb_item(name:"upnp/vuze_media_server/port", value:port);
    set_kb_item(name:"upnp/vuze_media_server/version",value:version);
}
else exit(0,"The service doesn't look like Vuze Media Server.");
