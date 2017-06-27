# nnposter
# GPL


include("compat.inc");

if (description)
    {
    script_id(25568);
    script_version ("$Revision: 1.7 $");

    name["english"]="Packeteer Web Management Interface Detection";
    script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is used to manage a network device." );
 script_set_attribute(attribute:"description", value:
"The remote web server is a Packeteer web management interface." );
 script_set_attribute(attribute:"see_also", value:"http://www.packeteer.com/" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_cvs_date("$Date: 2011/02/26 23:44:38 $");
 script_end_attributes();


    summary["english"]="Detects Packeteer web management interface";
    script_summary(english:summary["english"]);

    family["english"]="CGI abuses";
    script_family(english:family["english"]);

    script_category(ACT_GATHER_INFO);

    script_copyright(english:"This script is Copyright (c) 2007-2011 nnposter");
    script_dependencies("http_version.nasl");
    script_require_ports("Services/www",80);
    exit(0);
    }

# Notes:
# - Does not work with http_keepalive_send_recv() for some reason.
#   Resorting to http_send_recv()


include("http_func.inc");
#include("http_keepalive.inc");
include("misc_func.inc");


port=get_http_port(default:80);
if (!get_tcp_port_state(port)) exit(0);
encaps = get_kb_item("Transports/TCP/"+port);

#resp=http_keepalive_send_recv(port:port,data:http_get(item:"/login.htm",port:port));
resp=http_send_recv(port:port,data:http_get(item:"/login.htm",port:port));
if (!resp) exit(1, "The web server on port "+port+" failed to respond.");

server=egrep(pattern:"^Server: *httpd/1\.",string:resp,icase:TRUE);
if (!server) exit(0, "The web server on port "+port+" is not httpd/1.");
cookie=egrep(pattern:"^Set-Cookie: *[^a-z0-9]PScfgstr=",string:resp,icase:TRUE);
if (!cookie) exit(0, "The cookie cfgstr was not found on port "+port+".");

product="(unknown)";
# 8.x product extraction
match=eregmatch(pattern:': ([a-z]+) +Login</title>',string:resp,icase:TRUE);
if (isnull(match))
    # 7.x product extraction
    match=eregmatch(pattern:'\n([a-zA-Z]+) +/login\\.htm\n',string:resp);
if (!isnull(match)) product=match[1];

replace_kb_item(name:"www/packeteer",value:TRUE);
replace_kb_item(name:"www/"+port+"/packeteer",value:product);
if (product=="PacketShaper")
    replace_kb_item(name:"Services/www/"+port+"/embedded",value:TRUE);

issue="A Packeteer "+product+" web management interface is running on this port.";
if (encaps && (encaps >= ENCAPS_SSLv2 && encaps <= ENCAPS_TLSv1))
    {
    security_note(port:port,extra:issue);
    }
else
    {
    report = string(
"Consider disabling this port completely and using only HTTPS.  And
filter incoming traffic to this port. 
",
      "\n",
      issue
    );
    security_note(port:port,extra:report);
    set_kb_item(name: "packeteer/unencrypted", value: port);
    }
